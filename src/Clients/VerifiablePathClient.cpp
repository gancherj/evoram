#include "VerifiablePathClient.hpp"
#include "../common/Constants.hpp"
#include "../Crypto/Crypto.hpp"
#include <iostream>

// NOTE: I think --any-- network error (so failed assertion) should go to phase 2. If I was careful, I would catch boost throwing

using namespace std;
namespace Path {
    namespace Verifiable {
    Client::Client(std::string paramsfile, std::string ip, int port, std::string client_sk_filename, std::string server_pk_filename, std::string contract_addr_filename, std::string rpcaddr)
        :
        mHeight(-1)
        {

            Initialize(paramsfile, ip, port, client_sk_filename, server_pk_filename, contract_addr_filename, rpcaddr);
        }

    Client::~Client() {
        std::ofstream f1("../data/cverif/clientserverbytes", std::ios::app);
        f1 << mHeight << ", "<< mBlocksPerBucket << ", " << sizeof(EncryptedBlock) << ", "<< mBytesSentToServer << std::endl;
        f1.close();

        std::ofstream f2("../data/cverif/clientcverifbytes", std::ios::app);
        f2 << mHeight << ", "<< mBlocksPerBucket << ", " << sizeof(EncryptedBlock) << ", "<< mBytesSentToCVerif << std::endl;
        f2.close();


        std::ofstream file (CLIENT_PARAM_STORAGE_LOCATION, ios::binary);
        SaveStateAndClose(file, STASH_STORAGE_LOCATION);
        file.close();
    }

    size_t Client::GetBucketId(size_t assoc_leaf, size_t level)
    {
       //
       /*       1
        *     2   3
        *    4 5 6 7
        *
        * assumes leaves are labeled 0,1,2,...,num_leaves
        * and assumes levels are labeled 0,1,2,...,height-1 (descending)
        */
       return (1 << (level)) + (assoc_leaf >> ((mHeight - 1) - level));
   }

   bool Client::IsLeftChild(size_t bucketid) {
       return ((bucketid % 2 == 0) ? true : false);
   }

   SecByteBlock* Client::GetBucketKey (size_t bucketid)
   {
      if (mBucketKeys.count(bucketid) == 0)
      {
         Crypto::MakeKey(mBucketKeys[bucketid]);
      }
      return &mBucketKeys[bucketid];
   }

   // trim from end
static inline std::string &rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
            std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

   void Client::Initialize(std::string paramsfile, std::string ip, int port, std::string client_sk_filename, std::string server_pk_filename, std::string contract_addr_filename, std::string rpcaddr) {

       mServerConn.reset(new NetworkManager(ip, port, 4, true));
       mChannel = mServerConn->mChannel.get();

       std::ifstream params(paramsfile);
       params >> mUsingCVerifier >> mHeight >> mBlocksPerBucket;
       params.close();


       mBytesSentToCVerif = 0;
       mBytesSentToServer = 0;

       mHashSize = 32;
       mSigSize = 64;
       mRoot.reset(new char[mHashSize]);
       mPreviousRoot.reset(new char[mHashSize]);
       mNumLeaves = (1 << (mHeight - 1));
       mNumBuckets = (1 << mHeight) - 1;
       mBucketSize = mBlocksPerBucket * sizeof(EncryptedBlock);
       assert(sizeof(EncryptedBlock) % 32 == 0);

       mStash.SetPositionMap(&mPositionMap);

       assert(mHeight >= 1 && mHeight <= 63); // TODO is this necessary idk l o l

       if (mUsingCVerifier) {
         mCVerifierConn.reset(new NetworkManager("127.0.0.1", CLIENT_VERIF_PORT, 4, true));
         mCVerifierChannel = mCVerifierConn->mChannel.get();

         mClientPrivateKey = Crypto::ECCSig::LoadPrivKeyFromFile(client_sk_filename);
         mServerPublicKey = Crypto::ECCSig::LoadPubKeyFromFile(server_pk_filename);
       }
       else {
         mRPC.reset(new RPC::RPCWrapper(rpcaddr));
         mClientPrivateKey = Crypto::ECCSig::LoadPrivKeyFromFile(client_sk_filename);
         mServerPublicKey = Crypto::ECCSig::LoadPubKeyFromFile(server_pk_filename);
         mClientAddress = "0x" + Crypto::ECCSig::pk_to_addr(Crypto::ECCSig::PrivToPubKey(mClientPrivateKey));
         mServerAddress = "0x" + Crypto::ECCSig::pk_to_addr(mServerPublicKey);

         std::ifstream ifs(contract_addr_filename);
         std::string contractaddr( (std::istreambuf_iterator<char>(ifs) ),
         (std::istreambuf_iterator<char>()    ) );
         ifs.close();


         mContractAddress = rtrim(contractaddr);


         mRPC->WatchContract(mContractAddress);
         mRPC->Call(mClientAddress, mContractAddress, "ClientRegister(address,uint256,uint256,uint256,uint256)", {"address", "uint256", "uint256", "uint256", "uint256"},
         {Abi::ValueType::String(mServerAddress), Abi::ValueType::Uint(mHeight), Abi::ValueType::Uint(mBlocksPerBucket), Abi::ValueType::Uint(sizeof(EncryptedBlock) / 32),
           Abi::ValueType::Uint(120)}, 1); //120 = 2 minutes timeout
       }






       std::cout<<"Client initialized with height "<<mHeight<<", blocks per bucket "<<mBlocksPerBucket<<", block size" << sizeof(EncryptedBlock)<<std::endl;

       std::ofstream pp("../measure/client_gas", std::ios::app);
       pp << std::endl <<mHeight<<", "<<mBlocksPerBucket<<", "<<sizeof(EncryptedBlock);
       pp.close();

       assert(mServerConn);
      TellServerToHandshake();

       FillServerWithDummy();

   }

   bool Client::VerifyServerSignedRoot(Crypto::ECCSig::ECDSA_HexSignature sig, char* hash, size_t count) {
       std::string roothex = Crypto::ToHex(hash, mHashSize);
       std::string counthex = Abi::Encode::encode_uint(count);
       std::string msghex = roothex + counthex;
       std::vector<byte> msgvect = Crypto::FromHex(msghex);
       std::string msg((char*)msgvect.data(), msgvect.size());
       std::string sha = Crypto::SHA3(msg);
       return Crypto::ECCSig::Verify(mServerPublicKey, sha, sig);
   }
   bool Client::VerifyClientSignedRoot(Crypto::ECCSig::ECDSA_HexSignature sig, char* hash, size_t count) {
       std::string roothex = Crypto::ToHex(hash, mHashSize);
       std::string counthex = Abi::Encode::encode_uint(count);
       std::string msghex = roothex + counthex;
       std::vector<byte> msgvect = Crypto::FromHex(msghex);
       std::string msg((char*)msgvect.data(), msgvect.size());
       std::string sha = Crypto::SHA3(msg);
       return Crypto::ECCSig::Verify(Crypto::ECCSig::PrivToPubKey(mClientPrivateKey), sha, sig);
   }

   void Client::TellServerToHandshake() {
       std::unique_ptr<BinaryStream> outbuffer(new BinaryStream);
       *outbuffer << Command::ContractHandshake;
       mBytesSentToServer += outbuffer->size();
       mChannel->AsyncSendMessage(std::move(outbuffer));
       if (!mUsingCVerifier) {
         std::cout<<"Waiting for handshake from contract.."<<std::endl;

         mRPC->WaitForEvents({"Initialized()"}); // wait for contract to acknowledge server presence
       }
   }

   Crypto::ECCSig::ECDSA_HexSignature Client::SignRootAndCount() {
       std::string roothex = Crypto::ToHex(mRoot.get(), mHashSize);
       std::string counthex = Abi::Encode::encode_uint(mCount);
       std::string msghex = roothex + counthex;
       std::vector<byte> msgvect = Crypto::FromHex(msghex);
       std::string msg((char*)msgvect.data(), msgvect.size());
       std::string sha = Crypto::SHA3(msg);
       return Crypto::ECCSig::Sign(mClientPrivateKey, sha);
   }

   void Client::SendServerInitialSignedRoot() {
       Crypto::ECCSig::ECDSA_HexSignature hs = SignRootAndCount();
       std::unique_ptr<BinaryStream> outbuffer(new BinaryStream);
       *outbuffer << Command::InitialClientSig;
       *outbuffer << Crypto::ECCSig::SerializeSignature(hs);
       mBytesSentToServer += outbuffer->size();
       mChannel->AsyncSendMessage(std::move(outbuffer));
   }

   void Client::FillServerWithDummy() {
       std::unique_ptr<BinaryStream> outbuffer(new BinaryStream);
       *outbuffer << Command::DummyFill;

       EncryptedBlock dummy;
       for (size_t i = 1; i <= mNumBuckets; i++) {
            for (int j = 0; j < mBlocksPerBucket; j++) {
                MakeEncryptedDummyBlock(i, dummy);
                outbuffer->Write(&dummy, sizeof(EncryptedBlock));
            }
       }


       mChannel->AsyncSendMessage(std::move(outbuffer));
       std::cout<<"DummyFill done"<<std::endl;



       // now receive new root with signature w/ count = 0
       std::unique_ptr<BinaryStream> inbuffer(new BinaryStream);
       mChannel->RecvMessage(*inbuffer);
       assert(inbuffer->size() == mHashSize + mSigSize);

       char inroot[mHashSize];
       inbuffer->Read(inroot, mHashSize);
       bytes64 hexserial;
       inbuffer->Read(hexserial.data, mSigSize);

       mServerSig = Crypto::ECCSig::ParseSignature(hexserial);
       mCount = 0;

       assert(VerifyServerSignedRoot(mServerSig, inroot, mCount)); // NOTE: this one doesn't need to do proceed to phase 2; I'm assuming setup is correct

       memcpy(mRoot.get(), inroot, mHashSize);
       memcpy(mPreviousRoot.get(), mRoot.get(), mHashSize);

       std::cout<<"Got server signature: "<<mServerSig.r<<" , "<<mServerSig.s<<std::endl;

       SendServerInitialSignedRoot();

   }

   void Client::MakeEncryptedDummyBlock(size_t bucketid, EncryptedBlock& out) {
       //out->data = new char[Block::EncryptedDataSize];
       Crypto::MakeIV(out.iv);
       char dummydata[sizeof(Block)];
       std::fill(dummydata, dummydata + sizeof(Block), '\0');
       memset(dummydata, 0, sizeof(size_t)); // path specific
       std::string ct;
       Crypto::AESEncrypt(GetBucketKey(bucketid), out.iv, dummydata, sizeof(dummydata), ct);
       memcpy(out.data, ct.c_str(), sizeof(out.data));
   }

   void Client::SaveStateAndClose(std::ostream& out, std::string stashfilename) {
       out << "__Path_ORAM_Client_Parameter__" << endl;
       out << "     TreeHeight           =" << mHeight << endl;
       out << "     BlocksPerBucket =" << mBlocksPerBucket << endl;
       //out << "     BlockSize            =" << mBlockSize << endl;
       //out << "     BlockCount           =" << mBlockCount << endl;
       std::unique_ptr<BinaryStream> buffer(new BinaryStream);
       *buffer << Command::SaveState;
       mBytesSentToServer += buffer->size();

       mServerConn->mChannel->AsyncSendMessage(std::move(buffer));
       buffer.reset(new BinaryStream);
       buffer->Clear();
       *buffer << Command::CloseChannel;
       mBytesSentToServer += buffer->size();
       mServerConn->mChannel->SendMessage(buffer->HeadG(), buffer->size());
       mServerConn->mChannel->Stop();
       mChannel = nullptr;
       mServerConn->Stop();
       mStash.SaveToFileAndDelete(stashfilename);

       if (mUsingCVerifier) {
         buffer.reset(new BinaryStream);
         *buffer << Command::CloseChannel;
         mBytesSentToCVerif += buffer->size();
         mCVerifierChannel->SendMessage(buffer->HeadG(), buffer->size());
         mCVerifierChannel->Stop();
         mCVerifierConn->Stop();
       }
   }
   void Client::LoadState(std::istream& in, std::string stashfilename) {
       string token;
       in >> token;
       if (token != "__Ring_ORAM_Client_Parameter__") {
          throw std::runtime_error("Invalid Ring ORAM State stream(Header)");
       }

       //GetArg<size_t>(in, "EvictionPathIdx", mEvictionPathIdx._My_val);
       //GetArg<size_t>(in, "Round", mRound._My_val);
       mHeight = GetArg<size_t>(in, "TreeHeight");
       mBlocksPerBucket = GetArg<size_t>(in, "BlocksPerBucket");

       BinaryStream message;
       message << Command::LoadState;
       message << mHeight;
       message << mBlocksPerBucket;

       if(mServerConn->Stopped())
       {
          // happens if this is called after SaveState.
          mServerConn->Start();
          mServerConn->MakeChannel();
       }
       mBytesSentToServer += message.size();
       mServerConn->mChannel->AsyncSendMessageCopy(message.HeadG(), message.size());
       mStash.LoadFromFile(stashfilename);
   }


   size_t Client::GetRandomLeafAddr() {
      return Crypto::GetRandomLessThan(mNumLeaves);
   }

   std::string Client::HashBucket(std::string bucketdata, std::string lefthash, std::string righthash) {
       // in solidity, sha3(cur_bucket, cur_lower_left, cur_lower_right);
       std::string bucketdatahex = Crypto::ToHex(bucketdata);
       std::string lefthashhex = Crypto::ToHex(lefthash);
       std::string righthashhex = Crypto::ToHex(righthash);
       int zeroes_needed = 64 - (bucketdatahex.size() % 64);
       if (zeroes_needed == 64)
           zeroes_needed = 0;
       std::string hextohash = bucketdatahex + std::string(zeroes_needed, '0') + lefthashhex + righthashhex;
       std::vector<byte> d = Crypto::FromHex(hextohash);
       return Crypto::SHA3((char*)d.data(), d.size());
   }

   std::string Client::ReconstructRoot(size_t assoc_leaf, EncryptedBlock** path, std::string* proof) {
       std::string lowerLeftHash(mHashSize, 0);
       std::string lowerRightHash(mHashSize, 0);
       std::string curHash(mHashSize, 0);
       size_t dataSize = mBlocksPerBucket * sizeof(EncryptedBlock);


       EncryptedBlock* bucket;
       size_t level;

       for (int j = 1; j < mHeight; j++) {
           level = mHeight - j; //level ranges from mHeight - 1 (bottom) to 1 (right below root)
           bucket = path[level];

           curHash = HashBucket(std::string((char*)bucket, dataSize), lowerLeftHash, lowerRightHash);

           if (IsLeftChild(GetBucketId(assoc_leaf, level))) { // cur hash moves to left, proof moves to right
               lowerLeftHash = curHash;
               lowerRightHash = proof[level];
           }
           else {
               lowerRightHash = curHash;
               lowerLeftHash = proof[level];
           }
       }

       // now compute root
       bucket = path[0];

       curHash = HashBucket(std::string((char*)bucket, dataSize), lowerLeftHash, lowerRightHash);

       return curHash;
   }

   void Client::ReadMerkleProof(BinaryStream& in_buf, std::string* proof) {
       char tmp[mHashSize];
       for (int j = 1; j < mHeight; j++) {
           size_t level = mHeight - j;
           in_buf.Read(tmp, mHashSize);
           proof[level] = std::string(tmp, mHashSize);
       }
   }

   void Client::ReadPathFromServer(size_t assoc_leaf, EncryptedBlock** path, std::string* proof) {
       std::unique_ptr<BinaryStream> buffer(new BinaryStream);
       *buffer << Command::ReadPath;
       *buffer << assoc_leaf;
       mBytesSentToServer += buffer->size();

       mChannel->AsyncSendMessage(std::move(buffer));

       std::unique_ptr<BinaryStream> inbuffer(new BinaryStream);
       mChannel->RecvMessage(*inbuffer);
       assert(inbuffer->size() == (mHeight * mBlocksPerBucket * sizeof(EncryptedBlock) + (mHeight - 1) * mHashSize));

       for (size_t j = 1; j <= mHeight; j++) {
           size_t lvl = mHeight - j;
           for (size_t i = 0; i < mBlocksPerBucket; i++) {
               inbuffer->Read(&path[lvl][i], sizeof(EncryptedBlock));
           }
       }

       ReadMerkleProof(*inbuffer, proof);
   }

   void Client::MovePathIntoStash(size_t assoc_leaf, EncryptedBlock** path) {
       for (size_t j = 1; j <= mHeight; j++) {
           size_t lvl = mHeight - j;
           for (size_t i = 0; i < mBlocksPerBucket; i++) {
               EncryptedBlock* tmp_enc_block = &path[lvl][i];
               std::string ct(tmp_enc_block->data, sizeof(tmp_enc_block->data));
               Block* block_for_stash = new Block();
               Crypto::AESDecrypt(GetBucketKey(GetBucketId(assoc_leaf, lvl)), tmp_enc_block->iv, ct, block_for_stash, sizeof(Block));
               size_t blockid;
               memcpy(&blockid, block_for_stash->data, sizeof(size_t));
               if (blockid != 0) {
                   mStash.Insert(block_for_stash, blockid);
               }
               else {
                   delete block_for_stash;
               }

           }
       }
   }


   void Client::ReadPathFromServerIntoStash(size_t assoc_leaf, std::string* proof) {


       // NOTE: logical IDs are contained within the first sizeof(size_t) bytes of the data in Block

       EncryptedBlock** path = new EncryptedBlock*[mHeight];
       for (int lvl = 0; lvl < mHeight; lvl++)
            path[lvl] = new EncryptedBlock[mBlocksPerBucket];


       ReadPathFromServer(assoc_leaf, path, proof);

       // reconstruct and check path and proof

       std::string hash = ReconstructRoot(assoc_leaf, path, proof);
       bool valid = (hash == std::string(mRoot.get(), mHashSize));
       assert(valid); // TODO: "abort"; proceed to phase 2

       // decrypt blocks in path and insert into stash
       MovePathIntoStash(assoc_leaf, path);


       for (int lvl = 0; lvl < mHeight; lvl++)
            delete[] path[lvl];
       delete[] path;
   }

   void Client::ReadPathFromAbi(EncryptedBlock** path, std::string* proof, std::vector<Abi::ValueType>* abi_data) {
       assert(abi_data->size() == 2);
       std::string* pathstr = &((*abi_data)[0].str); // contiguous bytes in hex of each bucket, from leaf to root
       size_t read_head = 0;
       for (int j = 1; j <= mHeight; j++) {
           size_t lvl = mHeight - j;
           std::vector<byte> bucket_data = Crypto::FromHex(pathstr->substr(read_head, mBucketSize * 2));
           read_head += mBucketSize * 2;
           memcpy(path[lvl], bucket_data.data(), mBucketSize);
       }

       std::vector<std::string> abiproof = (*abi_data)[1].bytearr;
       for (int j = 1; j < mHeight; j++) {
           size_t lvl = mHeight - j;
           std::vector<byte> proofdata = Crypto::FromHex(abiproof[j]);
           proof[lvl] = std::string((char*)proofdata.data(), proofdata.size());
       }
   }

   void Client::ReadPathFromAbiIntoStash(size_t assoc_leaf, std::string* proof, std::vector<Abi::ValueType>* abi_data) {
       // NOTE: logical IDs are contained within the first sizeof(size_t) bytes of the data in Block

       EncryptedBlock** path = new EncryptedBlock*[mHeight];
       for (int lvl = 0; lvl < mHeight; lvl++)
            path[lvl] = new EncryptedBlock[mBlocksPerBucket];

    std::string s = "";
    std::vector<std::string>* v = &((*abi_data)[0]).bytearr;
    for (auto st : *v)
     s.append(st);
    (*abi_data)[0].str = s;

       ReadPathFromAbi(path, proof, abi_data);

       // reconstruct and check path and proof

       std::string hash = ReconstructRoot(assoc_leaf, path, proof);
       bool valid = (hash == std::string(mRoot.get(), mHashSize));
       assert(valid); // this should always succeed if contract is correct

       // decrypt blocks in path and insert into stash
       MovePathIntoStash(assoc_leaf, path);


       for (int lvl = 0; lvl < mHeight; lvl++)
            delete[] path[lvl];
       delete[] path;
   }

   std::unique_ptr<PathBlock> Client::Read(size_t block_idx) {
       Block empty;
       std::unique_ptr<Block> b = std::move(Access(block_idx, empty, Operation::Read));
       PathBlock* pb = new PathBlock;
       memcpy(pb->data, b.get()->data + sizeof(size_t), sizeof(pb->data));
       return std::unique_ptr<PathBlock>(pb);
   }

   void Client::Write(size_t block_idx, PathBlock& new_block) {
       Block b;
       memcpy(b.data, &block_idx, sizeof(size_t));
       memcpy(b.data + sizeof(size_t), new_block.data, sizeof(new_block.data));
       Access(block_idx, b, Operation::Write);

   }


   void Client::WriteBucketFromStashToNewPath(size_t assoc_leaf, size_t level, EncryptedBlock** newPath) { // just sends blocks, no command or metadata
       size_t bucketid = GetBucketId(assoc_leaf, level);
       SecByteBlock* bucketkey = GetBucketKey(bucketid);

       std::vector<std::tuple<Block*, size_t>> blocks_from_stash = mStash.FindBlocks(mBlocksPerBucket, assoc_leaf, level, mHeight);

       size_t num_real_blocks = blocks_from_stash.size();
       for (int i = 0; i < num_real_blocks; i++) { // write real blocks to server
           EncryptedBlock encblock;
           Crypto::MakeIV(encblock.iv);
           std::string ct;
           Crypto::AESEncrypt(bucketkey, encblock.iv, std::get<0>(blocks_from_stash[i]), sizeof(Block), ct);
           memcpy(encblock.data, ct.c_str(), sizeof(encblock.data));
           newPath[level][i] = encblock;
       }

       for (int j = num_real_blocks; j < mBlocksPerBucket; j++) { //write extra dummy blocks
           EncryptedBlock encdummy;
           MakeEncryptedDummyBlock(bucketid, encdummy);
           newPath[level][j] = encdummy;

       }

       // free real blocks
       for (auto tup: blocks_from_stash) {
           delete std::get<0>(tup);
       }
   }

   void Client::WriteNewPathToServer(BinaryStream* outbuf, EncryptedBlock** newPath) {
       for (int j = 1; j <= mHeight; j++) {
           size_t lvl = mHeight - j;
           for (int i = 0; i < mBlocksPerBucket; i++) {
               outbuf->Write(&newPath[lvl][i], sizeof(EncryptedBlock));
           }
       }
   }

   void Client::WritePath(size_t assoc_leaf, std::string* proof) {

       EncryptedBlock** newPath = new EncryptedBlock*[mHeight];
       for (int lvl = 0; lvl < mHeight; lvl++)
            newPath[lvl] = new EncryptedBlock[mBlocksPerBucket];

        for (size_t i = 1; i <= mHeight; i++) {
            size_t lvl = mHeight - i;
            WriteBucketFromStashToNewPath(assoc_leaf, lvl, newPath);
        }

       // write from stash out
       std::unique_ptr<BinaryStream> buffer(new BinaryStream);
       *buffer << Command::WritePath;
       *buffer << assoc_leaf;
       WriteNewPathToServer(buffer.get(), newPath);
       mBytesSentToServer += buffer->size();

       mChannel->AsyncSendMessage(std::move(buffer));

       // now, newPath is populated
       std::string newRoot = ReconstructRoot(assoc_leaf, newPath, proof);
       memcpy(mRoot.get(), newRoot.data(), mHashSize);


       for (int lvl = 0; lvl < mHeight; lvl++)
            delete[] newPath[lvl];
       delete[] newPath;
   }

   void Client::WritePathToHex(size_t assoc_leaf, std::string* proof, std::string* pathbytes) { // NOTE: modified mRoot
       EncryptedBlock** newPath = new EncryptedBlock*[mHeight];
       for (int lvl = 0; lvl < mHeight; lvl++)
            newPath[lvl] = new EncryptedBlock[mBlocksPerBucket];

        for (size_t i = 1; i <= mHeight; i++) {
            size_t lvl = mHeight - i;
            WriteBucketFromStashToNewPath(assoc_leaf, lvl, newPath);
        }

        std::string newroot = ReconstructRoot(assoc_leaf, newPath, proof);
        memcpy(mRoot.get(), newroot.data(), mHashSize);

        pathbytes->clear();
        size_t readhead = 0;
        for (int j = 1; j <= mHeight; j++) {
            int lvl = mHeight - j;

            pathbytes->append(Crypto::ToHex(newPath[lvl], mBucketSize));
        }

        for (int lvl = 0; lvl < mHeight; lvl++)
             delete[] newPath[lvl];
        delete[] newPath;
   }

   void Client::SigExchange() {
       Crypto::ECCSig::ECDSA_HexSignature hs = SignRootAndCount();
       std::unique_ptr<BinaryStream> outbuffer(new BinaryStream);
       *outbuffer << Command::SigExchange;
       outbuffer->Write(Crypto::ECCSig::SerializeSignature(hs).data, mSigSize);
       mBytesSentToServer += outbuffer->size();

       mChannel->AsyncSendMessage(std::move(outbuffer));

       std::unique_ptr<BinaryStream> inbuffer(new BinaryStream);
       mChannel->RecvMessage(*inbuffer);
       assert(inbuffer->size() == mSigSize);
       bytes64 sigserial;
       inbuffer->Read(sigserial.data, mSigSize);
       Crypto::ECCSig::ECDSA_HexSignature hs_server = Crypto::ECCSig::ParseSignature(sigserial);

       assert(VerifyServerSignedRoot(hs_server, mRoot.get(), mCount)); // TODO: "abort"; proceed to phase 2
       mServerSig = hs_server;
   }



   void Client::RememberCurrentState(size_t request_idx) {
       // save previous state in case we need to revert
       mPreviousBlockPosition = mPositionMap[request_idx];
       mPreviousCount = mCount;
       memcpy(mPreviousRoot.get(), mRoot.get(), mHashSize);
       mPreviousServerSig = mServerSig;
       mPreviousStash.CloneFrom(&mStash);
   }

   void Client::RevertState() {
       mCount = mPreviousCount;
       memcpy(mRoot.get(), mPreviousRoot.get(), mHashSize);
       mServerSig = mPreviousServerSig;
       mStash.CloneFrom(&mPreviousStash);

   }

   Block* Client::ProcessOp(size_t block_idx, Operation op, Block& new_block, ListStash* stash) {
       // if reading, get requested block from stash
       // if writing, write new block to stash
       bool is_in_stash = stash->Contains(block_idx); // is my block in the stash?

       Block* out;
       Block* block_for_stash = new Block;
       if (op == Operation::Read) {
            if (is_in_stash) {
                out = stash->Remove(block_idx);
                memcpy(block_for_stash->data, out->data, sizeof(block_for_stash->data));
            }
            else {
                std::cout<<"Error! Couldn't find blockid "<<block_idx<<std::endl;
                throw std::runtime_error("tried to read but not in stash after reading");
            }
       }
       else if (op == Operation::Write) {
           size_t tmp;
           memcpy(&tmp, new_block.data, sizeof(size_t));
           assert(block_idx == tmp); // path blocks must have their index embedded in data
            if (is_in_stash) {
                Block* tmpptr = stash->Remove(block_idx);
                delete tmpptr;
            }
            memcpy(block_for_stash->data, new_block.data, sizeof(new_block.data));
       }

       stash->Insert(block_for_stash, block_idx);

       return out;
   }

   std::unique_ptr<Block> Client::Access(size_t block_idx, Block& new_block, Operation op) {
       assert(block_idx != 0); // 0 reserved for dummy

       if (mPositionMap.count(block_idx) == 0) {
           mPositionMap[block_idx] = GetRandomLeafAddr();
       }

       RememberCurrentState(block_idx);

       size_t block_assoc_leaf = mPositionMap[block_idx];
       mPositionMap[block_idx] = GetRandomLeafAddr();


       std::string* proof = new std::string[mHeight];

       ReadPathFromServerIntoStash(block_assoc_leaf, proof); // read the path into stash

       Block* out = ProcessOp(block_idx, op, new_block, &mStash); // copy from stash, rewriting stash if necessary


       WritePath(block_assoc_leaf, proof);
       mCount++;
       SigExchange();

       delete[] proof;
       if (op == Operation::Read) {
           return std::unique_ptr<Block>(out);
       }
       else
           return nullptr;

   }

   void Client::SendServerVerifyRequest(size_t count) {
       std::unique_ptr<BinaryStream> buffer(new BinaryStream);
       *buffer << Command::VerifyRequest;
       *buffer << count;
       mBytesSentToServer += buffer->size();

       mChannel->AsyncSendMessage(std::move(buffer));

   }


   inline std::vector<std::string> SplitHexToBytes32(std::string &in) {
       std::vector<std::string> out;
       assert(in.size() % 64 == 0);
       for (int i = 0; i < in.size(); i += 64) {
           out.push_back(in.substr(i, 64));
       }
       return out;
   }

   std::unique_ptr<Block> Client::VerifiedContractAccess(size_t block_idx, Block& new_block, Operation op) { // we wouldn't call this for the real thing

       // TODO make path processing more efficient client side

       mRPC->StartRecording();

       if (mPositionMap.count(block_idx) == 0) {
           mPositionMap[block_idx] = GetRandomLeafAddr();
       }
       RememberCurrentState(block_idx); // just for testing purposes

       // TODO replace all WaitForEvents with a loop that calls poke if too much time has elapsed

       RevertState();

       std::string* proof = new std::string[mHeight];

       // NOTE: bytes and bytes32 need to be in hex string format!

       std::cout<<"Submitting client root.."<<std::endl;
       mRPC->Call(mClientAddress, mContractAddress, "client_submit_root(bytes32,uint256,bytes32,bytes32)",{"bytes32", "uint256", "bytes32", "bytes32"},
            {Abi::ValueType::String(Crypto::ToHex(mRoot.get(), 32)), // root_c
             Abi::ValueType::Uint(mCount), //count_c
             Abi::ValueType::String(mServerSig.r), // sigma_S (r)
             Abi::ValueType::String(mServerSig.s)}, 1); // sigma_S (s)

        SendServerVerifyRequest(mCount);

        RPC::Event e = mRPC->WaitForEvents({"Client_leaf_request()", "Cheat_client(string)", "Cheat_server(string)"});
        if (e.event_name != "Client_leaf_request()") { //someone cheated!
            std::cout<<"Cheat! "<<e.event_name<<std::endl;
            throw std::runtime_error("cheat");
        }


        // call client_submit_leaf(uint256) using mPreviousBlockPosition
        std::cout<<"Submitting request.."<<std::endl;
        mRPC->Call(mClientAddress, mContractAddress, "client_submit_leaf(uint256)", {"uint256"},
        {Abi::ValueType::Uint(mPreviousBlockPosition)}, 1);

       // wait for Client_new_path_request(bytes,bytes32[]) or Cheat_client(string) or Cheat_server(string)
       e = mRPC->WaitForEvents({"Client_new_path_request(bytes32[],bytes32[])","Cheat_client(string)","Cheat_server(string)"});
       if (e.event_name != "Client_new_path_request(bytes32[],bytes32[])") { //someone cheated!
           std::cout<<"Cheat! "<<e.event_name<<std::endl;
           throw std::runtime_error("cheat");
       }



       std::vector<Abi::ValueType> P = Abi::Decode::decode_data({"bytes32[]", "bytes32[]"}, e.data);
       assert(P.size() == 2);
       std::cout<<"Reading in path.."<<std::endl;
       ReadPathFromAbiIntoStash(mPreviousBlockPosition, proof, &P);

       Block* out = ProcessOp(block_idx, op, new_block, &mStash);


       std::string pathhex;
       WritePathToHex(mPreviousBlockPosition, proof, &pathhex); // modified mRoot
       mCount++;

       Crypto::ECCSig::ECDSA_HexSignature new_client_sig = SignRootAndCount();

       assert(VerifyClientSignedRoot(new_client_sig, mRoot.get(), mCount));

       std::cout<<"Submitting new path.."<<std::endl;

       Abi::ValueType a;
       a.bytearr = SplitHexToBytes32(pathhex);

       mRPC->Call(mClientAddress, mContractAddress, "client_submit_new_path(bytes32[],bytes32,uint256,bytes32,bytes32)", {"bytes32[]","bytes32","uint256","bytes32","bytes32"},
        {a,
         Abi::ValueType::String(Crypto::ToHex(mRoot.get(), 32)),
         Abi::ValueType::Uint(mCount),
         Abi::ValueType::String(new_client_sig.r),
         Abi::ValueType::String(new_client_sig.s)}, 1);



       // wait for Success(bytes32,bytes32) or Cheat_client(string) or Cheat_server(string)
       e = mRPC->WaitForEvents({"Success(bytes32,bytes32)", "Cheat_client(string)", "Cheat_server(string)"});
       if (e.event_name != "Success(bytes32,bytes32)") {
           std::cout<<"Cheat! " << e.event_name << std::endl;
           throw std::runtime_error("cheat");
       }
       std::cout<<"Verified access complete"<<std::endl;

       std::vector<Abi::ValueType> newserversig = Abi::Decode::decode_data({"bytes32","bytes32"}, e.data);
       assert(newserversig.size() == 2);
       mServerSig.r = newserversig[0].str;
       mServerSig.s = newserversig[1].str;

       delete[] proof;


       size_t gas_used = mRPC->SumUpGasInLog(1);
       std::ofstream gaslog("../measure/client_gas", std::ios::app);
       gaslog << ", " << gas_used << ", "; 
       gaslog.close();

       if (op == Operation::Read) {
           return std::unique_ptr<Block>(out);
       }
       else
           return nullptr;

   }

   std::unique_ptr<Block> Client::VerifiedCVerifierAccess(size_t block_idx, Block& new_block, Operation op) {

       if (mPositionMap.count(block_idx) == 0) {
           mPositionMap[block_idx] = GetRandomLeafAddr();
       }
       RememberCurrentState(block_idx); // just for testing purposes

       RevertState();

       SendServerVerifyRequest(mCount);

       std::string* proof = new std::string[mHeight];
       EncryptedBlock** path = new EncryptedBlock*[mHeight];
       for (int lvl = 0; lvl < mHeight; lvl++)
           path[lvl] = new EncryptedBlock[mBlocksPerBucket];
       std::cout<<"Submitting client root.."<<std::endl;
       // send verifier Command::VerifyRequest, mRoot, mCount, mServerSig as bytes64

       std::unique_ptr<BinaryStream> outbuf(new BinaryStream);
       *outbuf << Command::VerifyRequest;
       outbuf->Write(mRoot.get(), mHashSize);
       outbuf->Write(&mCount, sizeof(mCount));
       bytes64 serialsig = Crypto::ECCSig::SerializeSignature(mServerSig);
       outbuf->Write(&serialsig, sizeof(serialsig));

       mBytesSentToCVerif += outbuf->size();

       mCVerifierChannel->AsyncSendMessage(std::move(outbuf));


       // recieve Command::LeafRequest from verifier
       std::unique_ptr<BinaryStream> inbuf(new BinaryStream);
       mCVerifierChannel->RecvMessage(*inbuf);
       Command c;
       inbuf->Read(&c, sizeof(Command));
       assert(c == Command::LeafRequest);

       // send mPreviousBlockPosition to verifier
       std::cout<<"Submitting request.."<<std::endl;
        outbuf.reset(new BinaryStream);
        outbuf->Write(&mPreviousBlockPosition, sizeof(mPreviousBlockPosition));
        mBytesSentToCVerif += outbuf->size();
        mCVerifierChannel->AsyncSendMessage(std::move(outbuf));


       // receive path, proof from verifier; read in path
       inbuf.reset(new BinaryStream);
       mCVerifierChannel->RecvMessage(*inbuf);
       for (size_t j = 1; j <= mHeight; j++) {
           size_t lvl = mHeight - j;
           for (size_t i = 0; i < mBlocksPerBucket; i++) {
               inbuf->Read(&path[lvl][i], sizeof(EncryptedBlock));
           }
       }
       char tmp[mHashSize];
       for (int j = 1; j < mHeight; j++) {
           size_t level = mHeight - j;
           inbuf->Read(tmp, mHashSize);
           proof[level] = std::string(tmp, mHashSize);
       }
       std::string hash = ReconstructRoot(mPreviousBlockPosition, path, proof);
       bool valid = (hash == std::string(mRoot.get(), mHashSize));
       assert(valid);
       MovePathIntoStash(mPreviousBlockPosition, path);



       Block* out = ProcessOp(block_idx, op, new_block, &mStash);

       // write path out from stash to EncryptedBlock**

        for (size_t i = 1; i <= mHeight; i++) {
            size_t lvl = mHeight - i;
            WriteBucketFromStashToNewPath(mPreviousBlockPosition, lvl, path);
        }

        std::string newRoot = ReconstructRoot(mPreviousBlockPosition, path, proof);
        memcpy(mRoot.get(), newRoot.data(), mHashSize);

       mCount++;

       Crypto::ECCSig::ECDSA_HexSignature new_client_sig = SignRootAndCount();

       assert(VerifyClientSignedRoot(new_client_sig, mRoot.get(), mCount));

       std::cout<<"Submitting new path.."<<std::endl;

       // send verifier newpath, mRoot, mCount, new_client_sig as bytes64
       outbuf.reset(new BinaryStream);
       for (int j = 1; j <= mHeight; j++) {
           size_t lvl = mHeight - j;
           for (int i = 0; i < mBlocksPerBucket; i++) {
               outbuf->Write(&path[lvl][i], sizeof(EncryptedBlock));
           }
       }
       outbuf->Write(mRoot.get(), mHashSize);
       outbuf->Write(&mCount, sizeof(mCount));
       serialsig = Crypto::ECCSig::SerializeSignature(new_client_sig);
       outbuf->Write(&serialsig, sizeof(serialsig));
       mBytesSentToCVerif += outbuf->size();
       mCVerifierChannel->AsyncSendMessage(std::move(outbuf));

       for (int lvl = 0; lvl < mHeight; lvl++)
            delete[] path[lvl];
       delete[] path;

       // receive root, count, sig from verifier
       std::cout<<"Verified access complete"<<std::endl;
       inbuf.reset(new BinaryStream);
       mCVerifierChannel->RecvMessage(*inbuf);
       inbuf->Read(mRoot.get(), mHashSize);
       inbuf->Read(&mCount, sizeof(mCount));
       inbuf->Read(&serialsig, sizeof(serialsig));

       // store sig into mServerSig
       mServerSig = Crypto::ECCSig::ParseSignature(serialsig);


       delete[] proof;

       if (op == Operation::Read) {
           return std::unique_ptr<Block>(out);
       }
       else
           return nullptr;

   }

   std::unique_ptr<PathBlock> Client::VerifiedRead(size_t block_idx) {
       Block empty;
       std::unique_ptr<Block> b;
       if (mUsingCVerifier) {
         b = std::move(VerifiedCVerifierAccess(block_idx, empty, Operation::Read));
       }
       else {
         b = std::move(VerifiedContractAccess(block_idx, empty, Operation::Read));
       }
       PathBlock* pb = new PathBlock;
       memcpy(pb->data, b.get()->data + sizeof(size_t), sizeof(pb->data));
       return std::unique_ptr<PathBlock>(pb);
   }

   void Client::VerifiedWrite(size_t block_idx, PathBlock& new_block) {
       Block b;
       memcpy(b.data, &block_idx, sizeof(size_t));
       memcpy(b.data + sizeof(size_t), new_block.data, sizeof(new_block.data));
       if (mUsingCVerifier) {
         VerifiedCVerifierAccess(block_idx, b, Operation::Write);
       }
       else {
         VerifiedContractAccess(block_idx, b, Operation::Write);

       }

   }

   };
};

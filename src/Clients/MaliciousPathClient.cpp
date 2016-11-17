#include "MaliciousPathClient.hpp"
#include "../common/Constants.hpp"
#include "../Crypto/Crypto.hpp"
#include <iostream>

using namespace std;
namespace Path {
    namespace Malicious {
    Client::Client(std::string paramsfile, std::string ip, int port)
        :
        mHeight(-1)
        {
            Initialize(paramsfile, ip, port);
        }

    Client::~Client() {
        std::ofstream fil("../data/mal/clientbytessent", std::ios::app);
        fil << mHeight <<", "<<mBlocksPerBucket<<", "<<sizeof(EncryptedBlock)<<", " << mBytesSent << std::endl;
        fil.close();

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

   void Client::Initialize(std::string paramsfile, std::string ip, int port) {
       mServerConn.reset(new NetworkManager(ip, port, 4, true));
       mChannel = mServerConn->mChannel.get();

       std::ifstream params(paramsfile);
       bool b; // b unused for malicious
       params >> b >> mHeight >> mBlocksPerBucket;
       params.close();

       mHashSize = 32;
       mRoot.reset(new char[mHashSize]);
       mNumLeaves = (1 << (mHeight - 1));
       mNumBuckets = (1 << mHeight) - 1;
       mBytesSent = 0;

       mStash.SetPositionMap(&mPositionMap);

       assert(mHeight >= 1 && mHeight <= 63);

       std::cout<<"Client initialized with height "<<mHeight<<", blocks per bucket "<<mBlocksPerBucket<<std::endl;

       FillServerWithDummy();

       assert(mServerConn);
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

       // now receive new root
       std::unique_ptr<BinaryStream> inbuffer(new BinaryStream);
       mChannel->RecvMessage(*inbuffer);
       assert(inbuffer->size() == mHashSize);
       inbuffer->Read(mRoot.get(), mHashSize);

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
       mBytesSent += buffer->size();
       mServerConn->mChannel->AsyncSendMessage(std::move(buffer));
       buffer.reset(new BinaryStream);
       buffer->Clear();
       *buffer << Command::CloseChannel;
       mServerConn->mChannel->SendMessage(buffer->HeadG(), buffer->size());
       mServerConn->mChannel->Stop();
       mChannel = nullptr;
       mServerConn->Stop();
       mStash.SaveToFileAndDelete(stashfilename);
   }
   void Client::LoadState(std::istream& in, std::string stashfilename) {
       string token;
       // cout << "client start @ " << in.tellg() << endl;
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
       mBytesSent += message.size();
       mServerConn->mChannel->AsyncSendMessageCopy(message.HeadG(), message.size());
       mStash.LoadFromFile(stashfilename);
   }


   size_t Client::GetRandomLeafAddr() {
      return Crypto::GetRandomLessThan(mNumLeaves);
   }

   std::string Client::ReconstructRoot(size_t assoc_leaf, EncryptedBlock** path, std::string* proof) {
       std::string lowerLeftHash(mHashSize, 0);
       std::string lowerRightHash(mHashSize, 0);
       std::string curHash(mHashSize, 0);

       size_t hashInputSize = mBlocksPerBucket * sizeof(EncryptedBlock) + 2 * mHashSize;
       size_t dataSize = mBlocksPerBucket * sizeof(EncryptedBlock);
       char hashInput[hashInputSize];

       EncryptedBlock* bucket;
       size_t level;

       for (int j = 1; j < mHeight; j++) {
           level = mHeight - j; //level ranges from mHeight - 1 (bottom) to 1 (right below root)
           bucket = path[level];

           memcpy(hashInput, bucket, dataSize);
           memcpy(hashInput + dataSize, lowerLeftHash.data(), mHashSize);
           memcpy(hashInput + dataSize + mHashSize, lowerRightHash.data(), mHashSize);
           curHash = Crypto::SHA3(hashInput, hashInputSize);

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
       memcpy(hashInput, bucket, dataSize);
       memcpy(hashInput + dataSize, lowerLeftHash.data(), mHashSize);
       memcpy(hashInput + dataSize + mHashSize, lowerRightHash.data(), mHashSize);
       curHash = Crypto::SHA3(hashInput, hashInputSize);

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

   bool Client::ReadAndConfirmMerklePath(size_t assoc_leaf, EncryptedBlock** path, BinaryStream& in_buf, std::string* proof) {
       ReadMerkleProof(in_buf, proof);
       std::string hash = ReconstructRoot(assoc_leaf, path, proof);
       return (hash == std::string(mRoot.get(), mHashSize));
   }

   void Client::ReadPathFromServerIntoStash(size_t assoc_leaf, std::string* proof) {
       std::unique_ptr<BinaryStream> buffer(new BinaryStream);
       *buffer << Command::ReadPath;
       *buffer << assoc_leaf;
       mBytesSent += buffer->size();

       mChannel->AsyncSendMessage(std::move(buffer));

       std::unique_ptr<BinaryStream> inbuffer(new BinaryStream);
       mChannel->RecvMessage(*inbuffer);
       assert(inbuffer->size() == (mHeight * mBlocksPerBucket * sizeof(EncryptedBlock) + (mHeight - 1) * mHashSize));

       // NOTE: logical IDs are contained within the first sizeof(size_t) bytes of the data in Block

       EncryptedBlock** path = new EncryptedBlock*[mHeight];
       for (int lvl = 0; lvl < mHeight; lvl++)
            path[lvl] = new EncryptedBlock[mBlocksPerBucket];


       for (size_t j = 1; j <= mHeight; j++) {
           size_t lvl = mHeight - j;
           for (size_t i = 0; i < mBlocksPerBucket; i++) {
               inbuffer->Read(&path[lvl][i], sizeof(EncryptedBlock));
           }
       }
       bool valid = ReadAndConfirmMerklePath(assoc_leaf, path, *inbuffer, proof);
       assert(valid);
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


   void Client::WriteBucketFromStash(BinaryStream* outbuf, size_t assoc_leaf, size_t level, EncryptedBlock** newPath) { // just sends blocks, no command or metadata
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

           outbuf->Write(&encblock, sizeof(encblock));
           newPath[level][i] = encblock;
       }

       for (int j = num_real_blocks; j < mBlocksPerBucket; j++) { //write extra dummy blocks
           EncryptedBlock encdummy;
           MakeEncryptedDummyBlock(bucketid, encdummy);
           outbuf->Write(&encdummy, sizeof(encdummy));
           newPath[level][j] = encdummy;

       }

       // free real blocks
       for (auto tup: blocks_from_stash) {
           delete std::get<0>(tup);
       }
   }

   void Client::WritePath(size_t assoc_leaf, std::string* proof) {

       EncryptedBlock** newPath = new EncryptedBlock*[mHeight];
       for (int lvl = 0; lvl < mHeight; lvl++)
            newPath[lvl] = new EncryptedBlock[mBlocksPerBucket];


       // write from stash out
       std::unique_ptr<BinaryStream> buffer(new BinaryStream);
       *buffer << Command::WritePath;
       *buffer << assoc_leaf;
       for (size_t i = 1; i <= mHeight; i++) {
           size_t lvl = mHeight - i;
           WriteBucketFromStash(buffer.get(), assoc_leaf, lvl, newPath);
       }
       mBytesSent += buffer->size();

       mChannel->AsyncSendMessage(std::move(buffer));

       // now, newPath is populated
       std::string newRoot = ReconstructRoot(assoc_leaf, newPath, proof);
       memcpy(mRoot.get(), newRoot.data(), mHashSize);

       for (int lvl = 0; lvl < mHeight; lvl++)
            delete[] newPath[lvl];
       delete[] newPath;
   }

   std::unique_ptr<Block> Client::Access(size_t block_idx, Block& new_block, Operation op) {
       assert(block_idx != 0); // 0 reserved for dummy

       if (mPositionMap.count(block_idx) == 0) {
           mPositionMap[block_idx] = GetRandomLeafAddr();
       }
       size_t block_assoc_leaf = mPositionMap[block_idx];
       mPositionMap[block_idx] = GetRandomLeafAddr();

       std::string* proof = new std::string[mHeight];

       ReadPathFromServerIntoStash(block_assoc_leaf, proof); // read the path into stash

       bool is_in_stash = mStash.Contains(block_idx); // is my block in the stash?

       // if reading, get requested block from stash
       // if writing, write new block to stash
       Block* out;
       Block* block_for_stash = new Block;
       if (op == Operation::Read) {
            if (is_in_stash) {
                out = mStash.Remove(block_idx);
                memcpy(block_for_stash->data, out->data, sizeof(block_for_stash->data));
            }
            else {
                std::cout<<"Error! Couldn't find blockid "<<block_idx<<". Should have been on assoc leaf " << block_assoc_leaf<<std::endl;
                throw std::runtime_error("tried to read but not in stash after reading");
            }
       }
       else if (op == Operation::Write) {
           size_t tmp;
           memcpy(&tmp, new_block.data, sizeof(size_t));
           assert(block_idx == tmp); // path blocks must have their index embedded in data
            if (is_in_stash) {
                Block* tmpptr = mStash.Remove(block_idx);
                delete tmpptr;
            }
            memcpy(block_for_stash->data, new_block.data, sizeof(new_block.data));
       }

       mStash.Insert(block_for_stash, block_idx);

       WritePath(block_assoc_leaf, proof);

       delete[] proof;
       if (op == Operation::Read) {
           return std::unique_ptr<Block>(out);
       }
       else
           return nullptr;

   }
   };
};

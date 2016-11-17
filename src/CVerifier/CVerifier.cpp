#include "CVerifier.hpp"

namespace Path {
  namespace Verifiable {
    Verifier::Verifier(std::string client_pk_filename, std::string server_pk_filename, std::string paramsfile) {
      mServerNetManager.reset(new NetworkManager("127.0.0.1", SERVER_VERIF_PORT, 4, false));
      mClientNetManager.reset(new NetworkManager("127.0.0.1", CLIENT_VERIF_PORT, 4, false));

      mServerPublicKey = Crypto::ECCSig::LoadPubKeyFromFile(server_pk_filename);
      mClientPublicKey = Crypto::ECCSig::LoadPubKeyFromFile(client_pk_filename);

      std::ifstream params(paramsfile);
      bool b;
      params >> b >> mHeight >> mBlocksPerBucket;
      params.close();

      assert(b);

      mClientChannel = mClientNetManager->mChannel.get();
      mServerChannel = mServerNetManager->mChannel.get();

      mBucketSize = mBlocksPerBucket * sizeof(EncryptedBlock);
      mHashSize = 32;
    }

    void Verifier::MainLoop() {
      std::unique_ptr<BinaryStream> buffer;
      while(true) {
        buffer.reset(new BinaryStream);
        try {
          mClientChannel->RecvMessage(*buffer);
        }
        catch (std::exception e) {
          break;
        }
        Command code = *reinterpret_cast<Command*>(buffer->HeadG());
        if (code == Command::VerifyRequest) {
          buffer->SeekG(sizeof(Command));
          HandleVerifyRequest(buffer.get());
        }
        if (code == Command::CloseChannel) {
          mClientChannel->Stop();
          mServerChannel->Stop();
          mClientNetManager->Stop();
          mServerNetManager->Stop();
          break;
        }
        else {
          assert(-1);
        }
      }
    }

    size_t Verifier::GetBucketId(size_t assoc_leaf, size_t level)
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

   bool Verifier::IsLeftChild(size_t bucketid) {
       return ((bucketid % 2 == 0) ? true : false);
   }

    std::string Verifier::HashBucket(std::string bucketdata, std::string lefthash, std::string righthash) {
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

    std::string Verifier::ReconstructRoot(size_t assoc_leaf, EncryptedBlock** path, std::string* proof) {
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

    bool Verifier::VerifySignedRoot(Crypto::ECCSig::ECDSA_PubKey key, Crypto::ECCSig::ECDSA_HexSignature sig, char* hash, size_t count) {
        std::string roothex = Crypto::ToHex(hash, mHashSize);
        std::string counthex = Abi::Encode::encode_uint(count);
        std::string msghex = roothex + counthex;
        std::vector<byte> msgvect = Crypto::FromHex(msghex);
        std::string msg((char*)msgvect.data(), msgvect.size());
        std::string sha = Crypto::SHA3(msg);
        return Crypto::ECCSig::Verify(key, sha, sig);
    }

    void Verifier::DeletePath(EncryptedBlock** p) {
      for (int lvl = 0; lvl < mHeight; lvl++)
           delete[] p[lvl];
      delete[] p;
    }

    void Verifier::HandleVerifyRequest(BinaryStream* request_buf) {
      char root_c[32];
      size_t count_c;
      size_t request_leaf;
      EncryptedBlock** path = new EncryptedBlock*[mHeight];
      for (int lvl = 0; lvl < mHeight; lvl++)
           path[lvl] = new EncryptedBlock[mBlocksPerBucket];

      std::string* proof = new std::string[mHeight];
      bytes64 serialsig;
      Crypto::ECCSig::ECDSA_HexSignature sig;

      // read root (32bytes), count (sizet), sig (bytes64) from request_buf; new buf from then on
      // verify sig; send VerifyRequest to server
      request_buf->Read(root_c, 32);
      request_buf->Read(&count_c, sizeof(size_t));
      request_buf->Read(&serialsig, 64);
      sig = Crypto::ECCSig::ParseSignature(serialsig);
      if (!VerifySignedRoot(mServerPublicKey, sig, root_c, count_c)) {
        std::cout<<"Cheat!"<<std::endl;
        DeletePath(path);
        assert(-1);
      }

      std::unique_ptr<BinaryStream> outbuffer(new BinaryStream);
      *outbuffer << Command::VerifyRequest;
      mServerChannel->AsyncSendMessage(std::move(outbuffer));

      // read same as above from server
      // verify sig; send Command::LeafRequest to client

      std::unique_ptr<BinaryStream> inbuffer(new BinaryStream);
      mServerChannel->RecvMessage(*inbuffer);
      char root_s[32];
      size_t count_s;
      inbuffer->Read(root_s, 32);
      inbuffer->Read(&count_s, sizeof(size_t));
      inbuffer->Read(&serialsig, 64);
      sig = Crypto::ECCSig::ParseSignature(serialsig);
      if (!VerifySignedRoot(mClientPublicKey, sig, root_s, count_s)) {
        std::cout<<"Cheat!"<<std::endl;
        DeletePath(path);
        assert(-1);
      }
      if (count_s >= count_c + 2) {
        std::cout<<"Cheat!"<<std::endl;
        DeletePath(path);
        assert(-1);
      }
      if (count_s != count_c) {
        std::cout<<"Cheat!"<<std::endl;
        DeletePath(path);
        assert(-1);
      }

      outbuffer.reset(new BinaryStream);
      *outbuffer << Command::LeafRequest;
      mClientChannel->AsyncSendMessage(std::move(outbuffer));

      // read size_t from client
      // send same size_t to server
      inbuffer.reset(new BinaryStream);
      mClientChannel->RecvMessage(*inbuffer);
      inbuffer->Read(&request_leaf, sizeof(size_t));

      outbuffer.reset(new BinaryStream);
      *outbuffer << request_leaf;
      mServerChannel->AsyncSendMessage(std::move(outbuffer));


      // read pathdata (new char[bucket_size * mHeight]), proofdata (new char[32 * mHeight]) from server
      // reconstruct root; compare with client's submitted root
      inbuffer.reset(new BinaryStream);
      mServerChannel->RecvMessage(*inbuffer);
      for (size_t j = 1; j <= mHeight; j++) {
          size_t lvl = mHeight - j;
          for (size_t i = 0; i < mBlocksPerBucket; i++) {
              inbuffer->Read(&path[lvl][i], sizeof(EncryptedBlock));
          }
      }
      char tmp[mHashSize];
      for (int j = 1; j < mHeight; j++) {
          size_t level = mHeight - j;
          inbuffer->Read(tmp, mHashSize);
          proof[level] = std::string(tmp, mHashSize);
      }

      std::string hash = ReconstructRoot(request_leaf, path, proof);
      if (hash != std::string(root_c, 32)) {
        std::cout<<"Cheat!"<<std::endl;
        DeletePath(path);
        assert(-1);
      }

      outbuffer.reset(new BinaryStream);
      for (int j = 1; j <= mHeight; j++) {
          size_t lvl = mHeight - j;
          for (int i = 0; i < mBlocksPerBucket; i++) {
              outbuffer->Write(&path[lvl][i], sizeof(EncryptedBlock));
          }
      }
      for (int j = 1; j < mHeight; j++) {
          size_t level = mHeight - j;
          outbuffer->Write(proof[level].data(), mHashSize);
      }

      mClientChannel->AsyncSendMessage(std::move(outbuffer));

      // read pathdata (new char[bucket_size * mHeight]), root, count, sig from client
      // reconstruct root; verify sig; etc
      inbuffer.reset(new BinaryStream);
      mClientChannel->RecvMessage(*inbuffer);
      for (size_t j = 1; j <= mHeight; j++) {
          size_t lvl = mHeight - j;
          for (size_t i = 0; i < mBlocksPerBucket; i++) {
              inbuffer->Read(&path[lvl][i], sizeof(EncryptedBlock));
          }
      }
      char root_newc[32];
      size_t count_newc;
      inbuffer->Read(root_newc, 32);
      inbuffer->Read(&count_newc, sizeof(size_t));
      inbuffer->Read(&serialsig, 64);
      sig = Crypto::ECCSig::ParseSignature(serialsig);
      hash = ReconstructRoot(request_leaf, path, proof);
      if (!VerifySignedRoot(mClientPublicKey, sig, root_newc, count_newc) || count_newc != count_c + 1 || hash != std::string(root_newc, 32)) {
        std::cout<<"Cheat!"<<std::endl;
        DeletePath(path);
        assert(-1);
      }

      outbuffer.reset(new BinaryStream);
      for (int j = 1; j <= mHeight; j++) {
          size_t lvl = mHeight - j;
          for (int i = 0; i < mBlocksPerBucket; i++) {
              outbuffer->Write(&path[lvl][i], sizeof(EncryptedBlock));
          }
      }
      outbuffer->Write(root_newc, 32);
      outbuffer->Write(&count_newc, sizeof(size_t));
      outbuffer->Write(&serialsig, 64);
      mServerChannel->AsyncSendMessage(std::move(outbuffer));


      /// read root, count, sig from server; forward to client
      inbuffer.reset(new BinaryStream);
      mServerChannel->RecvMessage(*inbuffer);
      char root_news[32];
      size_t count_news;
      inbuffer->Read(root_news, 32);
      inbuffer->Read(&count_news, sizeof(size_t));
      inbuffer->Read(&serialsig, 64);
      sig = Crypto::ECCSig::ParseSignature(serialsig);
      if(!VerifySignedRoot(mServerPublicKey, sig, root_news, count_news) || count_news != count_newc || hash != std::string(root_news, 32)) {
        std::cout<<"Cheat!"<<std::endl;
        DeletePath(path);
        assert(-1);
      }

      outbuffer.reset(new BinaryStream);
      outbuffer->Write(root_news, 32);
      outbuffer->Write(&count_news, sizeof(size_t));
      outbuffer->Write(&serialsig, 64);
      mClientChannel->AsyncSendMessage(std::move(outbuffer));

      std::cout<<"Sucess!"<<std::endl;
      DeletePath(path);

    }
  }
}

#ifndef CVERIFIER_HPP
#define CVERIFIER_HPP

#include "../util/BinaryStream.hpp"
#include "../common/Defines.hpp"
#include "../util/NetworkManager.hpp"
#include "../util/StorageDevice.hpp"
#include "../abi/abi.hpp"
#include <string>
#include <iostream>
#include "../Crypto/Crypto.hpp"
#include <memory>


namespace Path {
  namespace Verifiable {
    class Verifier {
    public:
      Crypto::ECCSig::ECDSA_PubKey mServerPublicKey;
      Crypto::ECCSig::ECDSA_PubKey mClientPublicKey;

      size_t mHeight;
      size_t mBlocksPerBucket;
      size_t mBucketSize;
      size_t mHashSize;

      std::unique_ptr<NetworkManager> mClientNetManager;
      std::unique_ptr<NetworkManager> mServerNetManager;

      Channel* mClientChannel;
      Channel* mServerChannel;

      Verifier(std::string client_pk_filename, std::string server_pk_filename, std::string paramsfile);
      void MainLoop();
      void HandleVerifyRequest(BinaryStream* buf);

      std::string HashBucket(std::string bucketdata, std::string lefthash, std::string righthash);
      std::string ReconstructRoot(size_t assoc_leaf, EncryptedBlock** path, std::string* proof);
      bool VerifySignedRoot(Crypto::ECCSig::ECDSA_PubKey key, Crypto::ECCSig::ECDSA_HexSignature sig, char* hash, size_t count);

      size_t GetBucketId(size_t assoc_leaf, size_t level);
      bool IsLeftChild(size_t bucketid);
      void DeletePath(EncryptedBlock** p);

    };
  };
};

#endif

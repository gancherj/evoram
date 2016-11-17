#ifndef VERIFIABLE_PATHSERVER
#define VERIFIABLE_PATHSERVER

#include <vector>
#include <memory>
#include "../util/BinaryStream.hpp"
#include "../common/Defines.hpp"
#include <tuple>
#include "../util/NetworkManager.hpp"
#include "../util/StorageDevice.hpp"
#include <atomic>
#include "../Crypto/Crypto.hpp"

namespace Path {
    namespace Verifiable {
    class Server {
    public:
        std::unique_ptr<RAMBlockStorageDevice<char>> mDevice;
        size_t mHeight;
        size_t mNumBlocks;
        size_t mNumLeaves;
        size_t mNumBuckets;
        size_t mBlocksPerBucket;
        size_t mSizeofInternalBucket;
        std::string mStorageLocation;
        bool mUsingCVerifier;

        // previous state
        std::unique_ptr<char> mPreviousRoot;
        size_t mPreviousCount;
        Crypto::ECCSig::ECDSA_HexSignature mPreviousClientSig;
        std::unique_ptr<BinaryStream> mPreviousPath;
        size_t mPreviousPath_leaf;


        // ECC info
        Crypto::ECCSig::ECDSA_PrivKey mServerPrivateKey;
        Crypto::ECCSig::ECDSA_PubKey mClientPublicKey;
        size_t mSigSize;

        // Merkle tree info
        size_t mHashSize;
        std::unique_ptr<char> mRoot;
        size_t mCount;
        Crypto::ECCSig::ECDSA_HexSignature mClientSig;


        void SetState(std::string paramsfile, Crypto::ECCSig::ECDSA_PrivKey serversk, Crypto::ECCSig::ECDSA_PubKey clientpk, bool* usingcverifier);


        bool VerifyClientSignedRoot(Crypto::ECCSig::ECDSA_HexSignature sig, char* hash, size_t count);
        std::string HashBucket(std::string bucketdata, std::string lefthash, std::string righthash);
        void ConstructMerkleTree();
        void SendInitialMerkleRoot(BinaryStream& out);
        void SendMerkleProof(size_t assoc_leaf, BinaryStream& out);

        void GetInitialClientSig(BinaryStream& input_buffer);

        size_t GetBucketId(size_t assoc_leaf, size_t level);
        size_t GetSiblingId(size_t assoc_leaf, size_t level);
        size_t GetHashLocation(size_t bucketid);

        void DummyFill(BinaryStream& input_buffer, BinaryStream& out);

        void SigExchange(BinaryStream& input_buffer, BinaryStream& output_buffer);
        void ReadPath(size_t assoc_leaf, BinaryStream& output_buffer);
        void ReadDataPath(size_t assoc_leaf, BinaryStream& output_buffer);
        void WritePath(size_t assoc_leaf, BinaryStream& input_buffer);

        void SaveState(BinaryStream& input_buffer, BinaryStream& output_buffer);
        void LoadState(BinaryStream& input_buffer, BinaryStream& output_buffer);

        Crypto::ECCSig::ECDSA_HexSignature SignRootAndCount();

        // contract stuff
        void RememberCurrentState(size_t leaf_to_store);
        void RevertToPreviousState();
    };
}
};


#endif

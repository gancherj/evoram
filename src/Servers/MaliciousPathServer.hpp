#ifndef PATHSERVER
#define PATHSERVER

#include <vector>
#include <memory>
#include "../util/BinaryStream.hpp"
#include "../common/Defines.hpp"
#include <tuple>
#include "../util/NetworkManager.hpp"
#include "../util/StorageDevice.hpp"
#include <atomic>

namespace Path {
    namespace Malicious {
    class Server {
    private:
        //std::unique_ptr<MMFileBlockStorageDevice<char>> mDevice; // NOTE: using in-ram storage until this bus error gets figured out
        std::unique_ptr<RAMBlockStorageDevice<char>> mDevice;

    public:
      size_t mHeight;
      size_t mNumBlocks;
      size_t mNumLeaves;
      size_t mNumBuckets;
      size_t mBlocksPerBucket;
      size_t mSizeofBucket;
      size_t mHashSize;
      std::string mStorageLocation;
        void SetState(std::string paramsfile);

        void ConstructMerkleTree();
        void SendMerkleRoot(BinaryStream& out);
        void SendMerkleProof(size_t assoc_leaf, BinaryStream& out);
        size_t GetBucketId(size_t assoc_leaf, size_t level);
        size_t GetSiblingId(size_t assoc_leaf, size_t level);
        size_t GetHashLocation(size_t bucketid);
        void DummyFill(BinaryStream& input_buffer, BinaryStream& out);

        void ReadPath(size_t assoc_leaf, BinaryStream& output_buffer);
        void WritePath(size_t assoc_leaf, BinaryStream& input_buffer);

        void SaveState(BinaryStream& input_buffer, BinaryStream& output_buffer);
        void LoadState(BinaryStream& input_buffer, BinaryStream& output_buffer);
    };
}
};


#endif

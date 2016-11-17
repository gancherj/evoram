#ifndef PATH_CLIENT
#define PATH_CLIENT
#include "../util/NetworkManager.hpp"
#include "../common/Defines.hpp"
#include "ListStash.hpp"
#include <vector>
#include <utility>
#include "BaseClient.hpp"

namespace Path {
    namespace Malicious {


    class Client : public BaseClient {
    private:

        Channel* mChannel;

        // Server info
        std::unique_ptr<NetworkManager> mServerConn;
        std::string mStorageLocation;

        size_t mHashSize;
        std::unique_ptr<char> mRoot;

        // tree parameters
        size_t mHeight;
        size_t mBlocksPerBucket;
        size_t mNumBuckets;
        size_t mNumLeaves;
        size_t mBytesSent;

        std::unique_ptr<Block> Access(size_t block_idx, Block& new_block, Operation op);

        // Private/Internal Methods
        void SaveStateAndClose(std::ostream& out, std::string stashfilename);
        void LoadState(std::istream& in, std::string stashfilename);

        size_t GetBucketId(size_t assoc_leaf, size_t level);
        bool IsLeftChild(size_t bucketid);
        bool ReadAndConfirmMerklePath(size_t assoc_leaf, EncryptedBlock** path, BinaryStream& input, std::string* proof);
        SecByteBlock* GetBucketKey (size_t bucketid);
        size_t GetRandomLeafAddr();
        void MakeEncryptedDummyBlock(size_t bucketid, EncryptedBlock &out);

        void Initialize(std::string paramsfile, std::string ip, int port);
        void FillServerWithDummy();

        // server interaction
        void ReadPathFromServerIntoStash(size_t assoc_leaf, std::string* proof);
        void WriteBucketFromStash(BinaryStream* outbuf, size_t assoc_leaf, size_t level, EncryptedBlock** newPath); //just sends data; doesn't send command
        void WritePath(size_t assoc_leaf, std::string* proof);

        void ReadMerkleProof(BinaryStream& in_buf, std::string* proof);
        std::string ReconstructRoot(size_t assoc_leaf, EncryptedBlock** path, std::string* proof);
    public:
        Client(std::string paramsfile, std::string ip, int port);
        Client(const Client&) = delete;
        ~Client();
        void Write(size_t block_idx, PathBlock& new_block);
        std::unique_ptr<PathBlock> Read(size_t block_idx);


    };

}
};



#endif

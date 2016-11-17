#ifndef VERIFIABLE_PATH_CLIENT
#define VERIFIABLE_PATH_CLIENT
#include "../util/NetworkManager.hpp"
#include "../common/Defines.hpp"
#include "../RPCWrapper/RPCWrapper.hpp"
#include "ListStash.hpp"
#include <vector>
#include <utility>
#include "BaseClient.hpp"

namespace Path {
    namespace Verifiable {

    class Client : public BaseClient {
    private:

        size_t mBytesSentToServer;
        size_t mBytesSentToCVerif;

        // Server info
        Channel* mChannel;
        Channel* mCVerifierChannel;
        std::unique_ptr<NetworkManager> mServerConn;
        std::unique_ptr<NetworkManager> mCVerifierConn;
        std::string mStorageLocation;

        // Contract info
        std::string mClientAddress;
        std::string mServerAddress;
        std::string mContractAddress;
        std::unique_ptr<RPC::RPCWrapper> mRPC;

        bool mUsingCVerifier;

        // ECC info
        Crypto::ECCSig::ECDSA_PubKey mServerPublicKey;
        Crypto::ECCSig::ECDSA_PrivKey mClientPrivateKey;
        size_t mSigSize;

        // Merkle tree info
        size_t mHashSize;
        std::unique_ptr<char> mRoot;
        size_t mCount;
        Crypto::ECCSig::ECDSA_HexSignature mServerSig;

        // State saved in case of verified Access
        std::unique_ptr<char> mPreviousRoot;
        Crypto::ECCSig::ECDSA_HexSignature mPreviousServerSig;
        size_t mPreviousBlockPosition;
        size_t mPreviousCount;
        ListStash mPreviousStash;

        void RememberCurrentState(size_t idx);
        void RevertState();
        // tree parameters
        size_t mHeight;
        size_t mBlocksPerBucket;
        size_t mNumBuckets;
        size_t mNumLeaves;
        size_t mBucketSize;


        std::unique_ptr<Block> Access(size_t block_idx, Block& new_block, Operation op);

        // Private/Internal Methods
        void SaveStateAndClose(std::ostream& out, std::string stashfilename);
        void LoadState(std::istream& in, std::string stashfilename);

        void SendServerVerifyRequest(size_t count);

        bool VerifyClientSignedRoot(Crypto::ECCSig::ECDSA_HexSignature sig, char* hash, size_t count);

        size_t GetBucketId(size_t assoc_leaf, size_t level);
        bool IsLeftChild(size_t bucketid);
        SecByteBlock* GetBucketKey (size_t bucketid);
        size_t GetRandomLeafAddr();
        void MakeEncryptedDummyBlock(size_t bucketid, EncryptedBlock &out);

        void Initialize(std::string paramsfile, std::string ip, int port, std::string client_sk_filename, std::string server_pk_filename, std::string contract_addr_filename, std::string rpcaddr);

        void FillServerWithDummy();


        // server interaction
        Block* ProcessOp(size_t block_idx, Operation op, Block& new_block, ListStash* stash);
        void ReadPathFromServerIntoStash(size_t assoc_leaf, std::string* proof);
        void WriteBucketFromStashToNewPath(size_t assoc_leaf, size_t level, EncryptedBlock** newPath); //just sends data; doesn't send command
        void WriteNewPathToServer(BinaryStream* outbuf, EncryptedBlock** newPath);
        void WritePath(size_t assoc_leaf, std::string* proof);
        void MovePathIntoStash(size_t assoc_leaf, EncryptedBlock** path);
        void ReadPathFromServer(size_t assoc_leaf, EncryptedBlock** path, std::string* proof);
        void ReadMerkleProof(BinaryStream& in_buf, std::string* proof);
        std::string ReconstructRoot(size_t assoc_leaf, EncryptedBlock** path, std::string* proof);

        bool VerifyServerSignedRoot(Crypto::ECCSig::ECDSA_HexSignature sig, char* hash, size_t count);
        void SendServerInitialSignedRoot();

        void SigExchange();
         std::string HashBucket(std::string bucketdata, std::string lefthash, std::string righthash);

        Crypto::ECCSig::ECDSA_HexSignature SignRootAndCount();

        // contract interaction
        void TellServerToHandshake();
        std::unique_ptr<Block> VerifiedContractAccess(size_t block_idx, Block& new_block, Operation op);
        std::unique_ptr<Block> VerifiedCVerifierAccess(size_t block_idx, Block& new_block, Operation op);



        void ReadPathFromAbi(EncryptedBlock** path, std::string* proof, std::vector<Abi::ValueType>* abi_data);
        void ReadPathFromAbiIntoStash(size_t assoc_leaf, std::string* proof, std::vector<Abi::ValueType>* abi_data);

        void WritePathToHex(size_t assoc_leaf, std::string* proof, std::string* pathbytes);
    public:
        Client(std::string paramsfile, std::string ip, int port, std::string client_sk_filename, std::string server_pk_filename, std::string contract_addr_filename, std::string rpcaddr);
        Client(const Client&) = delete;
        ~Client();
        void Write(size_t block_idx, PathBlock& new_block);
        std::unique_ptr<PathBlock> Read(size_t block_idx);

        void VerifiedWrite(size_t block_idx, PathBlock& new_block);
        std::unique_ptr<PathBlock> VerifiedRead(size_t block_idx);

    };

}
};



#endif

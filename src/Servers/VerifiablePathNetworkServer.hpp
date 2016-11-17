#ifndef VERIF_PATH_NETWORK_SERVER
#define VERIF_PATH_NETWORK_SERVER
#include "../util/BinaryStream.hpp"
#include "../common/Defines.hpp"
#include "../util/NetworkManager.hpp"
#include "../util/StorageDevice.hpp"
#include "VerifiablePathServer.hpp"
#include "../abi/abi.hpp"
#include "../RPCWrapper/RPCWrapper.hpp"

namespace Path {
    namespace Verifiable {
    class NetworkServer {
    public:

        std::string mClientAddress;
        std::string mServerAddress;
        std::string mContractAddress;
        std::unique_ptr<RPC::RPCWrapper> mRPC;

        NetworkServer(std::string paramsfile, std::string ip, int port, std::string client_pk_filename, std::string server_sk_filename, std::string contract_addr_filename, std::string rpcaddr);
        ~NetworkServer();
        
        std::unique_ptr<NetworkManager> mNetManager;
        std::unique_ptr<NetworkManager> mCVerifierConn;
        Channel* mCVerifierChannel;
        bool mUsingCVerifier;
        Server mServer;

        void Init(std::string contract_addr_filename, std::string paramsfile, Crypto::ECCSig::ECDSA_PrivKey sk, Crypto::ECCSig::ECDSA_PubKey pk, std::string rpcaddr);
        void ReviveLoop(Channel* channel);
        void HandleContractRequest(size_t count);
        size_t HandleCVerifierRequest(size_t count);

    };
}
}
#endif

#ifndef VER_PATH_NETWORK_SERVER
#define VER_PATH_NETWORK_SERVER
#include "../util/BinaryStream.hpp"
#include "../common/Defines.hpp"
#include "../util/NetworkManager.hpp"
#include "../util/StorageDevice.hpp"
#include "MaliciousPathServer.hpp"

namespace Path {
    namespace Malicious {
    class NetworkServer {
    public:

        NetworkServer(std::string paramsfile, std::string ip, int port);
        NetworkManager mNetManager;
        Server mServer;

        void Init(std::string paramsfile);
        void ReviveLoop(Channel* channel);
    };
}
}
#endif

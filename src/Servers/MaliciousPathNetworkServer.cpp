// based off Peter's code

#include "MaliciousPathNetworkServer.hpp"
#include "../util/BinaryStream.hpp"
#include "../common/Defines.hpp"
#include "MaliciousPathServer.hpp"
#include "../Crypto/Crypto.hpp"
#include <iostream>
#include <memory>
#include <vector>


namespace Path {
    namespace Malicious {
    NetworkServer::NetworkServer(std::string paramsfile, std::string ip, int port) : mNetManager(ip, port, 4, false) {

        Init(paramsfile);


    }

    void NetworkServer::Init(std::string paramsfile) {
        mServer.SetState(paramsfile);
        ReviveLoop(mNetManager.mChannel.get());
    }

    void NetworkServer::ReviveLoop(Channel* channel) {
        BinaryStream buffer;
        size_t bytes_sent = 0;
        try {
            while(true) {
                channel->RecvMessage(buffer);

                std::string temp_str;
                Command code = *reinterpret_cast<Command*>(buffer.HeadG());
                switch (code) {
                    case Command::SaveState:
                    {
                       std::cout << "saving state" << std::endl;
                       channel->Stop();
                       mNetManager.Stop();

                       std::ofstream b("../data/mal/serverbytessent", std::ios::app);
                       b << mServer.mHeight << ", " << mServer.mBlocksPerBucket << ", " << sizeof(EncryptedBlock) << ", "<<bytes_sent << std::endl;
                       b.close();

                       return;
                       break;
                    }
                    case Command::LoadState:
                    {
                       std::cout << "loading state" << std::endl; //TODO i don't think this is doing anything yet
                       //mServer.SetState();
                       break;

                    }
                    case Command::CloseChannel:
                    {

                       channel->Stop();
                       if (channel->m_channel_idx == 0)
                       {
                          assert(mNetManager.mChannel);

                          mNetManager.Stop();

                          #ifdef DSE_SERVER_MESSAGING
                          std::cout << "Connection closed. Waiting For new Connection..." << std::endl;
                          #endif
                          mNetManager.mChannel = nullptr;

                          mNetManager.Start();

                          mNetManager.MakeChannel();


                          #ifdef DSE_SERVER_MESSAGING
                          std::cout << "Connection established." << std::endl;
                          #endif

                          channel = mNetManager.mChannel.get();
                       }
                       else
                       {
                          return;
                       }
                       break;
                    }
                    case Command::Terminate:
                    {
                       #ifdef DSE_SERVER_MESSAGING
                       std::cout << "Terminating" << std::endl;
                       #endif

                       assert(mNetManager.mChannel);
                       channel->Stop();

                       mNetManager.Stop();
                       return;
                    }
                    case Command::DummyFill:
                    {
                       std::cout << "DummyFill" << std::endl;
                       buffer.SeekG(sizeof(Command));

                       std::unique_ptr<BinaryStream> outbuf(new BinaryStream);
                       mServer.DummyFill(buffer, *outbuf);
                       bytes_sent += outbuf->size();
                       channel->AsyncSendMessage(std::move(outbuf));
                       break;
                    }
                    case Command::ReadPath: {
                        buffer.SeekG(sizeof(Command));
                        size_t assoc_leaf;
                        buffer >> assoc_leaf;
                        std::unique_ptr<BinaryStream> outbuf(new BinaryStream);
                        mServer.ReadPath(assoc_leaf, *outbuf);
                        bytes_sent += outbuf->size();
                        channel->AsyncSendMessage(std::move(outbuf));
                        break;
                    }
                    case Command::WritePath: {
                        buffer.SeekG(sizeof(Command));
                        size_t assoc_leaf;
                        buffer >> assoc_leaf;
                        mServer.WritePath(assoc_leaf, buffer);
                        break;
                    }
                    default:
                        break;
                }
                buffer.Clear();
            }
        }
        catch (std::exception& ee) {
            std::cout<<"Error: "<<ee.what() << std::endl;
        }
    }
}
}

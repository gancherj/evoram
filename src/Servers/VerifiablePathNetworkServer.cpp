// based off Peter's code

#include "VerifiablePathNetworkServer.hpp"
#include "../util/BinaryStream.hpp"
#include "../common/Defines.hpp"
#include "VerifiablePathServer.hpp"
#include "../Crypto/Crypto.hpp"
#include "../abi/abi.hpp"
#include <iostream>
#include <memory>
#include <vector>


namespace Path {
    namespace Verifiable {
        // trim from end
static inline std::string &rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
            std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}
    NetworkServer::NetworkServer(std::string paramsfile, std::string ip, int port, std::string client_pk_filename, std::string server_sk_filename, std::string contract_addr_filename, std::string rpcaddr)  {
        Crypto::ECCSig::ECDSA_PrivKey sk = Crypto::ECCSig::LoadPrivKeyFromFile(server_sk_filename);
        Crypto::ECCSig::ECDSA_PubKey pk = Crypto::ECCSig::LoadPubKeyFromFile(client_pk_filename);

        mNetManager.reset(new NetworkManager(ip, port, 4, false));
        Init(contract_addr_filename, paramsfile, sk, pk, rpcaddr);


    }

    NetworkServer::~NetworkServer() {
      if (mUsingCVerifier) {
        mCVerifierChannel->Stop();
        mCVerifierConn->Stop();
      }
    }

    void NetworkServer::Init(std::string contract_addr_filename, std::string paramsfile, Crypto::ECCSig::ECDSA_PrivKey sk, Crypto::ECCSig::ECDSA_PubKey pk, std::string rpcaddr) {
        mServer.SetState(paramsfile, sk, pk, &mUsingCVerifier);
        if (mUsingCVerifier) {
          mCVerifierConn.reset(new NetworkManager("127.0.0.1", SERVER_VERIF_PORT, 4, true));
          mCVerifierChannel = mCVerifierConn->mChannel.get();
        }
        else {
          mRPC.reset(new RPC::RPCWrapper(rpcaddr));
          std::ifstream ifs(contract_addr_filename);
          std::string contractaddr( (std::istreambuf_iterator<char>(ifs) ),
                             (std::istreambuf_iterator<char>()    ) );

          mClientAddress = "0x" + Crypto::ECCSig::pk_to_addr(pk);
          mServerAddress = "0x" + Crypto::ECCSig::pk_to_addr(Crypto::ECCSig::PrivToPubKey(sk));
          mContractAddress = rtrim(contractaddr);
          mRPC->WatchContract(mContractAddress);
          mRPC->SetEventListener("Cheat_server(string)");
          mRPC->SetEventListener("Cheat_client(string)");
          mRPC->SetEventListener("Server_verify_request(uint256)");
        }
        ReviveLoop(mNetManager->mChannel.get());
    }

    inline std::vector<std::string> SplitHexToBytes32(std::string &in) {
        std::vector<std::string> out;
        assert(in.size() % 64 == 0);
        for (int i = 0; i < in.size(); i += 64) {
            out.push_back(in.substr(i, 64));
        }
        return out;
    }

    void NetworkServer::HandleContractRequest(size_t count) {
        // TODO replace all WaitForEvents with a loop that calls poke if too much time has elapsed
        // TODO make path processing more efficient server side

        mRPC->StartRecording();

        //mServer.RevertToPreviousState(); TODO if I was doing this from phase 1
        assert(count == mServer.mCount); // TODO i think this needs to always hold after reverting??

        std::cout<<"Waiting for request.."<<std::endl;
        RPC::Event e = mRPC->WaitForEvents({"Server_verify_request(uint256)", "Cheat_client(string)", "Cheat_server(string)"});
        if (e.event_name != "Server_verify_request(uint256)")
            throw std::runtime_error("cheat!" + e.event_name);
        std::cout<<"found event"<<std::endl;


        std::cout<<"Submitting server root.."<<std::endl;
        // call function server_submit_root(bytes32 root_s, uint256 count_s, bytes32 R_c, bytes32 S_c)
        mRPC->Call(mServerAddress, mContractAddress, "server_submit_root(bytes32,uint256,bytes32,bytes32)", {"bytes32","uint256","bytes32","bytes32"}, {
            Abi::ValueType::String(Crypto::ToHex(mServer.mRoot.get(), 32)),
            Abi::ValueType::Uint(mServer.mCount),
            Abi::ValueType::String(mServer.mClientSig.r),
            Abi::ValueType::String(mServer.mClientSig.s)
        },2);

        e = mRPC->WaitForEvents({"Server_path_request(uint256)", "Cheat_client(string)", "Cheat_server(string)"});
        if (e.event_name != "Server_path_request(uint256)")
            throw std::runtime_error("cheat!" + e.event_name);

        size_t assoc_leaf = Abi::Decode::decode_data({"uint256"}, e.data)[0].unsigned_int;

        std::cout<<"Getting path/proof to send.."<<std::endl;
        // call function server_submit_path(bytes path, bytes32[] proof)
        std::unique_ptr<BinaryStream> readbuf(new BinaryStream);
        mServer.ReadPath(assoc_leaf, *readbuf); // outbuf contains block data (size = bucket_size * mServer.mHeight) and then merkle proof data (mServer.mHeight * mServer.mHashSize)
        size_t bucket_size = mServer.mBlocksPerBucket * sizeof(EncryptedBlock);
        char* pathdata = new char[bucket_size * mServer.mHeight];
        readbuf->Read(pathdata, bucket_size * mServer.mHeight);
        std::string hexpathdata = Crypto::ToHex(pathdata, bucket_size * mServer.mHeight);
        delete[] pathdata;

        std::vector<std::string> hashes;
        char hash[mServer.mHashSize];
        hashes.push_back(std::string(64, '0')); // to make align with 'proof' object in client code
        for (int i = 1; i < mServer.mHeight; i++) {
            readbuf->Read(hash, mServer.mHashSize);
            hashes.push_back(Crypto::ToHex(hash, mServer.mHashSize));
        }

        Abi::ValueType a; a.bytearr = SplitHexToBytes32(hexpathdata);
        Abi::ValueType p; p.bytearr = hashes;

        std::cout<<"Sending path.."<<std::endl;
        mRPC->Call(mServerAddress, mContractAddress, "server_submit_path(bytes32[],bytes32[])", {"bytes32[]", "bytes32[]"}, {
            a,
            p
        },2);
        //event Server_new_path_forward(bytes path, bytes32 newroot, uint newcount, bytes32 newR, bytes32 newS);
        std::cout<<"Reading in path.."<<std::endl;
        e = mRPC->WaitForEvents({"Server_new_path_forward(bytes32[],bytes32,uint256,bytes32,bytes32)", "Cheat_client(string)", "Cheat_server(string)"});
        if (e.event_name != "Server_new_path_forward(bytes32[],bytes32,uint256,bytes32,bytes32)")
            throw std::runtime_error("cheat!" + e.event_name);


        std::vector<Abi::ValueType> newpathabi = Abi::Decode::decode_data({"bytes32[]", "bytes32", "uint256", "bytes32", "bytes32"}, e.data);
        std::vector<std::string> newpathhexarr = newpathabi[0].bytearr;
        std::string newpathhex = "";
        for (std::string s : newpathhexarr)
            newpathhex.append(s);
        std::vector<byte> newpathdata = Crypto::FromHex(newpathhex);
        std::vector<byte> newrootdata = Crypto::FromHex(newpathabi[1].str); // i know this is correct by the contract
        size_t newcount = newpathabi[2].unsigned_int;

        BinaryStream newpathbuf; newpathbuf.Write(newpathdata.data(), newpathdata.size());
        mServer.WritePath(assoc_leaf, newpathbuf);
        assert(std::string(mServer.mRoot.get(), mServer.mHashSize) == std::string((char*)newrootdata.data(), mServer.mHashSize));
        mServer.mCount = newcount;
        mServer.mClientSig.r = newpathabi[3].str;
        mServer.mClientSig.s = newpathabi[4].str;

        std::cout<<"Submitting new root.."<<std::endl;
        Crypto::ECCSig::ECDSA_HexSignature newserversig = mServer.SignRootAndCount();
        mRPC->Call(mServerAddress, mContractAddress, "server_submit_new_root(bytes32,uint256,bytes32,bytes32)", {"bytes32","uint256","bytes32","bytes32"}, {
            Abi::ValueType::String(Crypto::ToHex(mServer.mRoot.get(), mServer.mHashSize)),
            Abi::ValueType::Uint(mServer.mCount),
            Abi::ValueType::String(newserversig.r),
            Abi::ValueType::String(newserversig.s)
        },2);

        e = mRPC->WaitForEvents({"Success(bytes32,bytes32)", "Cheat_client(string)", "Cheat_server(string)"});

        if (e.event_name == "Cheat_client(string)" || e.event_name == "Cheat_server(string)")
            throw std::runtime_error("Cheat!");
        else
            std::cout<<"Verified access success"<<std::endl;

        size_t gas_used = mRPC->SumUpGasInLog(1);
        std::ofstream gaslog("../measure/server_gas", std::ios::app);
        gaslog << ", " << gas_used << ", ";
        gaslog.close();

    }

    size_t NetworkServer::HandleCVerifierRequest(size_t count) {
        size_t bytessent = 0;
        assert(count == mServer.mCount); // TODO i think this needs to always hold after reverting??

        std::unique_ptr<BinaryStream> inbuf(new BinaryStream);
        mCVerifierChannel->RecvMessage(*inbuf);



        std::cout<<"Submitting server root.."<<std::endl;
        // send verifier mServer.mRoot, mServer.mCount, mServer.mClientSig as bytes64
        std::unique_ptr<BinaryStream> outbuf(new BinaryStream);
        bytes64 serialsig;
        outbuf->Write(mServer.mRoot.get(), mServer.mHashSize);
        outbuf->Write(&mServer.mCount, sizeof(mServer.mCount));
        serialsig = Crypto::ECCSig::SerializeSignature(mServer.mClientSig);
        outbuf->Write(&serialsig, sizeof(serialsig));
        bytessent += outbuf->size();
        mCVerifierChannel->AsyncSendMessage(std::move(outbuf));

        inbuf.reset(new BinaryStream);
        mCVerifierChannel->RecvMessage(*inbuf);

        // get assoc_leaf from server
        size_t assoc_leaf;
        inbuf->Read(&assoc_leaf, sizeof(assoc_leaf));



        std::cout<<"Getting path/proof to send.."<<std::endl;
        // send verifier data, proof
        outbuf.reset(new BinaryStream);
        mServer.ReadPath(assoc_leaf, *outbuf); // outbuf contains block data (size = bucket_size * mServer.mHeight) and then merkle proof data (mServer.mHeight * mServer.mHashSize)
        bytessent += outbuf->size();

        mCVerifierChannel->AsyncSendMessage(std::move(outbuf));


        // read in path, root, count, sig from verifier
        std::cout<<"Reading in path.."<<std::endl;


        inbuf.reset(new BinaryStream);
        mCVerifierChannel->RecvMessage(*inbuf);
        mServer.WritePath(assoc_leaf, *inbuf);
        //inbuf now has root, count, sig
        char newroot[32];
        inbuf->Read(newroot, 32);
        assert(std::string(newroot, 32) == std::string(mServer.mRoot.get(), 32));
        inbuf->Read(&mServer.mCount, sizeof(mServer.mCount));
        inbuf->Read(&serialsig, sizeof(serialsig));
        mServer.mClientSig = Crypto::ECCSig::ParseSignature(serialsig);


        // send verifier root, count, sig
        outbuf.reset(new BinaryStream);
        std::cout<<"Submitting new root.."<<std::endl;

        Crypto::ECCSig::ECDSA_HexSignature newserversig = mServer.SignRootAndCount();

        outbuf->Write(mServer.mRoot.get(), mServer.mHashSize);
        outbuf->Write(&mServer.mCount, sizeof(mServer.mCount));
        serialsig = Crypto::ECCSig::SerializeSignature(newserversig);
        outbuf->Write(&serialsig, sizeof(serialsig));
        bytessent += outbuf->size();
        mCVerifierChannel->AsyncSendMessage(std::move(outbuf));

        return bytessent;
    }

    void NetworkServer::ReviveLoop(Channel* channel) {
        BinaryStream buffer;
        size_t bytes_sent_to_client = 0;
        size_t bytes_sent_to_cverif = 0;
        try {
            while(true) {
                channel->RecvMessage(buffer);

                std::string temp_str;
                Command code = *reinterpret_cast<Command*>(buffer.HeadG());
                switch (code) {
                    case Command::ContractHandshake:  {
                        if (!mUsingCVerifier) {
                          std::cout<<"Sending handshake to contract.."<<std::endl;
                          mRPC->WaitForEvents({"Server_handshake_request(address)"});
                          mRPC->Call(mServerAddress, mContractAddress, "server_handshake()", {}, {},2);

                        }
                        break;
                    }
                    case Command::VerifyRequest: {
                        size_t count;
                        buffer.SeekG(sizeof(Command));
                        buffer >> count;
                        std::cout<<"Handling verify request with count "<<count<<std::endl;
                        if (mUsingCVerifier)
                          bytes_sent_to_cverif += HandleCVerifierRequest(count);
                        else
                          HandleContractRequest(count);
                        break;
                    }
                    case Command::SaveState:
                    {
                       std::cout << "saving state" << std::endl;
                       channel->Stop();
                       mNetManager->Stop();

                       std::ofstream f1("../data/cverif/serverclientbytes", std::ios::app);
                       f1 << mServer.mHeight << ", " << mServer.mBlocksPerBucket << ", " << sizeof(EncryptedBlock) << ", " << bytes_sent_to_client << std::endl;
                       f1.close();

                       std::ofstream f2("../data/cverif/servercverifbytes", std::ios::app);
                       f2 << mServer.mHeight << ", " << mServer.mBlocksPerBucket << ", " << sizeof(EncryptedBlock) << ", " << bytes_sent_to_cverif << std::endl;
                       f2.close();

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
                          assert(mNetManager->mChannel);

                          mNetManager->Stop();

                          #ifdef DSE_SERVER_MESSAGING
                          std::cout << "Connection closed. Waiting For new Connection..." << std::endl;
                          #endif
                          mNetManager->mChannel = nullptr;

                          mNetManager->Start();

                          mNetManager->MakeChannel();


                          #ifdef DSE_SERVER_MESSAGING
                          std::cout << "Connection established." << std::endl;
                          #endif

                          channel = mNetManager->mChannel.get();
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

                       assert(mNetManager->mChannel);
                       channel->Stop();

                       mNetManager->Stop();
                       return;
                    }
                    case Command::DummyFill:
                    {
                       std::cout << "DummyFill" << std::endl;
                       buffer.SeekG(sizeof(Command));

                       std::unique_ptr<BinaryStream> outbuf(new BinaryStream);
                       mServer.DummyFill(buffer, *outbuf);
                       bytes_sent_to_client += outbuf->size();
                       channel->AsyncSendMessage(std::move(outbuf));
                       //mServer.RememberCurrentState(0);
                       //mServer.RevertToPreviousState();
                       break;
                    }
                    case Command::ReadPath: {
                        std::cout<<"ReadPath"<<std::endl;
                        buffer.SeekG(sizeof(Command));
                        size_t assoc_leaf;
                        buffer >> assoc_leaf;
                        //mServer.RememberCurrentState(assoc_leaf);
                        std::unique_ptr<BinaryStream> outbuf(new BinaryStream);
                        mServer.ReadPath(assoc_leaf, *outbuf);
                        bytes_sent_to_client += outbuf->size();

                        channel->AsyncSendMessage(std::move(outbuf));
                        break;
                    }
                    case Command::WritePath: {
                        std::cout<<"WritePath"<<std::endl;
                        buffer.SeekG(sizeof(Command));
                        size_t assoc_leaf;
                        buffer >> assoc_leaf;
                        mServer.WritePath(assoc_leaf, buffer);
                        break;
                    }
                    case Command::InitialClientSig: {
                        std::cout<<"Initial client sig"<<std::endl;
                        buffer.SeekG(sizeof(Command));
                        mServer.GetInitialClientSig(buffer);
                        //mServer.RememberCurrentState(0);
                        break;
                    }
                    case Command::SigExchange: {
                        std::cout<<"Signature exchange"<<std::endl;
                        buffer.SeekG(sizeof(Command));
                        std::unique_ptr<BinaryStream> outbuf(new BinaryStream);
                        mServer.SigExchange(buffer, *outbuf);
                        bytes_sent_to_client += outbuf->size();

                        channel->AsyncSendMessage(std::move(outbuf));
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

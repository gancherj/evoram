/**
 * This file is generated by jsonrpcstub, DO NOT CHANGE IT MANUALLY!
 */

#ifndef JSONRPC_CPP_STUB_SENDCLIENT_H_
#define JSONRPC_CPP_STUB_SENDCLIENT_H_

#include <jsonrpccpp/client.h>

class ethclient : public jsonrpc::Client
{
    public:
        ethclient(jsonrpc::IClientConnector &conn, jsonrpc::clientVersion_t type = jsonrpc::JSONRPC_CLIENT_V2) : jsonrpc::Client(conn, type) {}

        std::string eth_sendTransaction(const std::string& data, const std::string& from, const std::string& to) throw (jsonrpc::JsonRpcException)
        {
            Json::Value t;
            t["data"] = data;
            t["from"] = from;
            t["to"] = to;
            t["gas"] = "0x47a760";
            Json::Value p;
            p.append(t);
            Json::Value result = this->CallMethod("eth_sendTransaction",p);
            if (result.isString())
                return result.asString();
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        std::string eth_getGasUsedInTransaction(std::string txhash) {
            //returns gas used as hex value
            Json::Value t;
            t.append(txhash);
            Json::Value result = this->CallMethod("eth_getTransactionReceipt", t);
            std::string h = result["gasUsed"].asString();
            return h; //i chop off the 0x
        }


        std::string eth_newFilterListenAll(const std::string& address) {
            Json::Value t;
            t["address"] = address;
            Json::Value p;
            p.append(t);
            Json::Value result = this->CallMethod("eth_newFilter", p);
            return result.asString();

        }

        Json::Value eth_getFilterChanges(const std::string& id) { //assumes only called by eth_newFilter
            Json::Value p;
            p.append(id);
            Json::Value result = this->CallMethod("eth_getFilterChanges", p);
            return result;
        }

        std::string eth_uninstallFilter(const std::string& id) {
            Json::Value p;
            p.append(id);
            Json::Value result = this->CallMethod("eth_uninstallFilter", p);
            return result.asString();
        }

        std::string eth_compileContract(const std::string& source) {
            Json::Value p;
            p.append(source);
            Json::Value res = this->CallMethod("eth_compileSolidity", p);
            return res.asString();
        }
};

#endif //JSONRPC_CPP_STUB_SENDCLIENT_H_

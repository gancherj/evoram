#include "RPCWrapper/RPCWrapper.hpp"
#include <string>
#include <fstream>

static inline std::string &rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
            std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

int main() {
    RPC::RPCWrapper rpc("http://localhost:8545");
    std::ifstream ifs("../data/contract.addr");
    std::string contractaddr( (std::istreambuf_iterator<char>(ifs) ),
                       (std::istreambuf_iterator<char>()    ) );
    std::string tx = rpc.Call("0x0954c55469a6306cb518815eccf5d3acee9f06b6", rtrim(contractaddr), "reset()", {}, {},1);
    std::cout<<"transaction receipt is " << tx <<std::endl;

    size_t gas = rpc.GasUsedBlocking(tx);

    std::cout<<"gas used for reset: "<<gas<<std::endl;
}

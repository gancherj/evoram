#include "Servers/VerifiablePathNetworkServer.hpp"
#include <boost/asio.hpp>
#include <iostream>


#include <time.h>
#include <stdint.h>

#include "common/Defines.hpp"


using namespace std;


int main(int argc, char** argv)
{
   Path::Verifiable::NetworkServer server("../data/params", "127.0.0.1", 9091, "../data/client.pk", "../data/server.sk", "../data/contract.addr", "http://localhost:8545");
}

#include "Servers/MaliciousPathNetworkServer.hpp"
#include <boost/asio.hpp>
#include <iostream>


#include <time.h>
#include <stdint.h>

#include "common/Defines.hpp"


using namespace std;


int main(int argc, char** argv)
{
   int port = 9091;
   std::cout<<"listening on port " << port << std::endl;
   Path::Malicious::NetworkServer server("../data/params", "127.0.0.1", port);
}

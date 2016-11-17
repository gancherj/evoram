//binary search using oram
#include "Clients/MaliciousPathClient.hpp"
#include "common/Defines.hpp"
#include "common/Constants.hpp"


#include <vector>
#include <iostream>
#include <time.h>
#include <stdint.h>
#include <fstream>

using namespace std;
using namespace Path;

using Malicious::Client;

size_t virtual_bandwidth = 0;

int main(int argc, char** argv)
{

   int port = 9091;
   std::string ip = "127.0.0.1";
   int m;
   std::cin >> m;
   std::cout<<"running experiment "<<m<<" times"<<std::endl;

   size_t height;
   size_t blocksperbucket;
   std::ifstream params("../data/params");
   bool b;
   params >> b >> height >> blocksperbucket;
   params.close();

   Client client("../data/params", ip, port);
   for (int i = 0; i < m; i++) {
       PathBlock block = PathBlock();
       client.Write(1, block);
       virtual_bandwidth += sizeof(PathBlock);
   }

   std:ofstream bandwidth("../data/mal/virtualbandwidth", std::ios::app);
   bandwidth<<m<<", "<<height<<", "<<blocksperbucket<<", "<<virtual_bandwidth<<std::endl;
   bandwidth.close();

   std::cout<<"virtual bandwidth: "<<virtual_bandwidth<<std::endl;
}

//binary search using oram
#include "Clients/VerifiablePathClient.hpp"
#include "common/Defines.hpp"
#include "common/Constants.hpp"


#include <vector>
#include <iostream>
#include <time.h>
#include <stdint.h>
#include <fstream>
#include <chrono>
typedef std::chrono::high_resolution_clock Clock;


using namespace std;
using namespace Path;

using Verifiable::Client;
int main(int argc, char** argv)
{
   size_t virt = 0;
   int port = 9091;
   std::string ip = "127.0.0.1";
   int m;
   std::cin >> m;
   bool verif;
   std::cin >> verif;

   size_t height;
   size_t blocksperbucket;
   std::ifstream params("../data/params");
   bool b;
   params >> b >> height >> blocksperbucket;
   params.close();

   std::cout<<"Running "<<m<<" accesses"<<std::endl;
   Client client("../data/params", ip, port, "../data/client.sk", "../data/server.pk", "../data/contract.addr", "http://localhost:8545");

   std::ofstream o("../measure/timings", std::ios::app);
   for (int i = 0; i < m; i++) {
     auto t1 = Clock::now();
       PathBlock block = PathBlock();
       if (verif)
        client.VerifiedWrite(1, block);
       else
        client.Write(1, block);
       virt += sizeof(PathBlock);
       auto t2 = Clock::now();
       auto int_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);
       o << m << ", " << height <<", "<<blocksperbucket<<", " << sizeof(PathBlock) << ", " << (1 << height) * blocksperbucket * sizeof(PathBlock) << ", " << (float)int_ms.count() / 1000 << std::endl;
   }
   o.close();
}

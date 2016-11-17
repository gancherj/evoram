//binary search using oram
#include "Clients/VerifiablePathClient.hpp"
#include "common/Defines.hpp"
#include "common/Constants.hpp"


#include <vector>
#include <iostream>
#include <time.h>
#include <stdint.h>
#include <fstream>

using namespace std;
using namespace Path;

using Verifiable::Client;




void WriteInt(Client& client, int val, int blockid)
{
   PathBlock block = PathBlock();
   memcpy(block.data, &val, sizeof(val));
   client.VerifiedWrite(blockid, block);
}

int GetInt(Client& client, int blockid)
{
   std::unique_ptr<PathBlock> blockptr = std::move(client.VerifiedRead(blockid));
   int out;
   memcpy(&out, blockptr->data, sizeof(out));
   return out;
}

int midpoint(int a, int b)
{
   return (a + b) / 2;
}

int BinarySearch(Client& client, int val, int start, int stop)
{
   while(stop >= start)
   {
      int mid = midpoint(start, stop);
      int test_val = GetInt(client, mid);
      if(test_val == val)
      {
         return mid;
      }
      else if (test_val < val)
      {
         start = mid + 1;
      }
      else if (test_val > val)
      {
         stop = mid - 1;
      }
   }
   return -1;
}

int main(int argc, char** argv)
{

   int port = 9091;
   std::string ip = "127.0.0.1";
   Client client("../data/params", ip, port, "../data/client.sk", "../data/server.pk", "../data/contract.addr", "http://localhost:8545");
   size_t num_real_blocks = 1000000;

   for (int i = 1; i < num_real_blocks/2 + 1; i++)
      WriteInt(client, i, i);

   for (int i = 1; i < num_real_blocks/2 + 1; i++) {
      int val_to_find = i;
      int start = 1;
      int end = num_real_blocks/2;
      int output = BinarySearch(client, val_to_find, start, end);
      std::cout << "Found " << val_to_find << " at index " << output << std::endl;
   }
}

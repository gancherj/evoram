//binary search using oram
#include "RingClient.hpp"
#include "Defines.hpp"
#include "Constants.hpp"


#include <vector>
#include <iostream>
#include <time.h>
#include <stdint.h>
#include <fstream>
#include "ProgressBar.hpp"

using namespace std;
using namespace Ring;





void WriteInt(Client& client, int val, int blockid)
{
   Block block = Block();
   memcpy(block.data, &val, sizeof(val));
   client.Write(blockid, block);
}

int GetInt(Client& client, int blockid)
{
   std::unique_ptr<Block> blockptr = std::move(client.Read(blockid));
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
   el::Configurations conf("../logs/binarysearchlogs.conf");
   el::Loggers::reconfigureLogger("default", conf);
   el::Loggers::reconfigureAllLoggers(conf);
   LOG(INFO) << "checking logs";

   int port = 9091;
   std::string ip = "127.0.0.1";
   Client client(ip, port);
   size_t num_real_blocks = ((1 << HEIGHT) - 1) * REAL_BLOCKS_PER_BUCKET;

   for (int i = 1; i < num_real_blocks + 1; i++)
      WriteInt(client, i, i);

   for (int i = 1; i < num_real_blocks + 1; i++) {
      int val_to_find = i;
      int start = 1;
      int end = num_real_blocks+1;
      int output = BinarySearch(client, val_to_find, start, end);
      std::cout << "Found " << val_to_find << " at index " << output << std::endl;
   }
}

//#define STASH_TEST //just for testing the stash

#include <list>
#include "../common/Defines.hpp"
#include "ListStash.hpp"
#include <tuple>
#include <vector>
#include <cstdio>
#include <iostream>
#include <thread>
#include <chrono>

   void ListStash::Print()
   {
      //std::cout<<"Printing stash"<<std::endl;
      for (auto it = mList.begin(); it != mList.end(); ++it)
      {
         std::cout<<std::get<1>(*it)<<std::endl;

         //LOG(INFO) << std::get<0>(*it)->data<<','<<std::get<1>(*it);
      }
   }

   void ListStash::Insert(Block* data, size_t blockid)
   {


       //LOG(INFO) << "ListStash::Insert Inserting (blockid: "<< blockid << ", assoc_leaf: " << assoc_leaf << ")" ;

      #ifdef STASH_TEST

       mList.push_front(std::make_tuple(data, blockid));
       return;

      #else

      size_t assoc_leaf = (*posmap)[blockid];

      if (mList.size() == 0)
      {
         mList.push_front(std::make_tuple(data, blockid));
         return;
      }
      else
      {
         for (auto it = mList.begin(); it != mList.end(); ++it)
         {
            // store in ascending order of assoc_leaf; makes FindBlocks faster
            if ((*posmap)[std::get<1>(*it)] > assoc_leaf)
            {
               mList.insert(it, std::make_tuple(data, blockid));
               return;
            }
         }
         // if we pass through the for loop and the data needs to do on the end
         mList.push_back(std::make_tuple(data, blockid));
      }
      #endif
   }

   bool ListStash::ContainsDuplicate(size_t blockidx)
   {
      int count = 0;
      for (auto it = mList.begin(); it != mList.end(); ++it)
      {
         if (std::get<1>(*it) == blockidx)
            count++;
      }
      if (count < 2)
         return false;
      else
         return true;
   }

   bool ListStash::Contains(size_t blockidx) {
       for (auto it = mList.begin(); it != mList.end(); ++it) {
           if (std::get<1>(*it) == blockidx)
            return true;
       }
       return false;
   }

   void ListStash::SetPositionMap(std::map<size_t, size_t>* mp)
   {
      posmap = mp;
   }



   void ListStash::CloneFrom(ListStash* other) {
       for (auto it = mList.begin(); it != mList.end(); ++it) {
           Block* b = std::get<0>(*it);
           delete b;
       }
       mList.clear();

       for (auto it = other->mList.begin(); it != other->mList.end(); ++it) {
           Block* b = new Block();
           memcpy(b->data, std::get<0>(*it)->data, Block::data_size);
           Insert(b, std::get<1>(*it));
       }

       posmap = other->posmap;
   }

   Block* ListStash::Remove(size_t blockid)
   {
      //LOG(INFO) <<"Looking in stash for blockid "<<blockid;
      for (auto it = mList.begin(); it != mList.end(); ++it)
      {
         if (std::get<1>(*it) == blockid)
         {
            Block* out = std::get<0>(*it);
            mList.erase(it);
            return out;
         }
      }
      //LOG(INFO) << "Stash failed to find blockid " << blockid;
      // sleep so that log file gets written to
      std::this_thread::sleep_for(std::chrono::seconds(2));
      throw std::runtime_error("Block not found on stash");
   }

   std::vector<std::tuple<Block*, size_t>>
      ListStash::FindBlocks (size_t how_many, size_t assoc_leaf, size_t level, size_t level_count)
   {
      size_t denom = level_count - level - 1;

      //LOG(INFO) << "FindBlocks with assoc_leaf " << assoc_leaf << " and level " << level ;
      std::vector<std::tuple<Block*, size_t>> out;

      for (auto it = mList.begin(); it != mList.end(); ++it)
      {

         size_t bl_assoc_leaf = (*posmap)[std::get<1>(*it)];
         if ((assoc_leaf >> denom) == (bl_assoc_leaf >> denom)) {
            //LOG(INFO) << "Adding (blockid " << std::get<1>(*it) << ", assoc_leaf " << assoc_leaf << ")";
            out.push_back(*it);
            it = mList.erase(it);
         }

         if (out.size() == how_many) {
            break;
         }
      }
      //LOG(INFO)<<"FindBlocks giving up blockids ";
      // for (auto t : out) {
      //    LOG(INFO) << std::get<1>(t) << " ";
      // }
      return out;
   }

   void ListStash::SaveToFileAndDelete (std::string filename)
   {
      size_t elt_size = sizeof(Block) + sizeof(size_t);
      size_t num = mList.size();
      std::unique_ptr<StorageDevice> device(new
                        MMFileBlockStorageDevice<char>(filename, num * elt_size + sizeof(size_t)+1));
      size_t head = 1;

      device->PWrite(head, &num, sizeof(num));
      head += sizeof(num);
      //LOG(INFO) <<"Writing "<<num<<" elements";
      for (auto it = mList.begin(); it != mList.end(); ++it)
      {
         auto elt = *it;
         device->PWrite(head, std::get<0>(elt), sizeof(Block));
         head += sizeof(Block);

         device->PWrite(head, &std::get<1>(elt), sizeof(size_t));
         head += sizeof(size_t);

         delete std::get<0>(elt);
      }
      written = true;
      deleted = true;
   }

   void ListStash::LoadFromFile (std::string filename)
   {
      assert(mList.empty());
      size_t elt_size = sizeof(Block) + sizeof(size_t);
      std::unique_ptr<StorageDevice> device(new
                        MMFileBlockStorageDevice<char>(filename, sizeof(size_t)+1));
      size_t head = 1;
      size_t num;
      device->PRead(head, &num, sizeof(num));
      device.reset(new MMFileBlockStorageDevice<char>(filename, sizeof(size_t) + num * elt_size + 1));
      head = 1 + sizeof(num);
      for (int i = 0; i < num; i++)
      {
         Block* newblock = new Block;
         size_t blockid;

         device->PRead(head, newblock, sizeof(Block));
         head += sizeof(Block);

         device->PRead(head, &blockid, sizeof(blockid));
         head += sizeof(blockid);

         mList.push_back(std::make_tuple(newblock, blockid));
      }
   }

   ListStash::~ListStash()
   {
      if (!written)
      {
         SaveToFileAndDelete(STASH_STORAGE_LOCATION);
      }
      if (!deleted)
      {
         for (auto it = mList.begin(); it != mList.end(); ++it)
         {
             delete std::get<0>(*it);
         }
      }
   }

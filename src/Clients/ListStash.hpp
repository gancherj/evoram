#ifndef LISTSTASH_HPP
#define LISTSTASH_HPP

#include <list>
#include "../util/StorageDevice.hpp"
#include "../common/Defines.hpp"
#include <vector>
#include <tuple>
#include <string>
#include <iostream>

class ListStash
{
public:
    // fields correspond to data, blockid
    std::list<std::tuple<Block*, size_t>> mList;

    ~ListStash();
    void Insert(Block* data, size_t blockid);
    Block* Remove(size_t idx);
    void CloneFrom(ListStash* other);
    std::vector<std::tuple<Block*, size_t>> FindBlocks(size_t how_many,
        size_t leaf_addr, size_t level, size_t level_count);
        //how_many is a max; we may find less
        void LoadFromFile(std::string filename);
        void SaveToFileAndDelete(std::string filename);
        void Print();
        bool ContainsDuplicate(size_t blockidx);
        bool Contains(size_t blockidx);
        void SetPositionMap(std::map<size_t, size_t>* mp);
        std::map<size_t, size_t>* posmap;
    private:
        bool written = false;
        bool deleted = false;
    };

#endif

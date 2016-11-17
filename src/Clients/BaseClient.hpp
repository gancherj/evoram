#ifndef BASECLIENT_HPP
#define BASECLIENT_HPP
#include <vector>
#include <utility>
#include "ListStash.hpp"

class BaseClient { 
public:
    ListStash mStash;
    std::map<size_t, size_t> mPositionMap;
    std::map<size_t, SecByteBlock> mBucketKeys;
};

#endif

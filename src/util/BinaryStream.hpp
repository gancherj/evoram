/* Written mostly by Peter */

#ifndef RING_BINARYSTREAM
#define RING_BINARYSTREAM

#include "../common/Defines.hpp"
#include "StorageDevice.hpp"

#include <iostream>
#include <vector>
#include <cinttypes>
#include <iterator>
#include <algorithm>
#include <array>


class BinaryStream {
public:
  BinaryStream()
     : mCapacity(128),
       mPutHead(0),
       mGetHead(0),
       mBuffer(new char[128])
  {}

  BinaryStream(size_t capacity)
     : mCapacity(capacity),
       mPutHead(0),
       mGetHead(0),
       mBuffer(new char[capacity])
  {}

  ~BinaryStream()
  {
     try{
        delete[] mBuffer;
     }
     catch (std::exception& ba)
     {
        std::cerr << "exception caught: " << ba.what() << '\n';
     }
  }
  inline void Clear() { mPutHead = mGetHead = 0; }
  inline size_t size() { { return mPutHead; } }

  inline void Reserve(size_t size)
  {
     if (mCapacity < size)
     {
        Grow(size);
     }
  }

  inline void CheckForCapacity(size_t added)
  {
     auto newHead = mPutHead + added;

     if (mCapacity > newHead) {} // compiler hint
     else
     {
        try
        {
           Grow(newHead);
        }
        catch (std::bad_alloc& ba)
        {
           std::cerr << "bad_alloc caught: " << ba.what() << '\n';
        }
     }
  }
private:
  inline void Grow(size_t minNewSize)
  {
     auto newCap = mCapacity << 1;
     while (newCap < minNewSize) newCap <<= 1;

     char* newBuffer = new char[newCap];
     memcpy(newBuffer, mBuffer, mCapacity);
     delete[] mBuffer;
     mBuffer = newBuffer;
     mCapacity = newCap;
  }
public:
  inline void operator << (const bool& data){

     CheckForCapacity(sizeof(data));

     auto begin = reinterpret_cast<const char*>(&data);
     memcpy(mBuffer + mPutHead, begin, sizeof(data));
     SeekP(mPutHead + sizeof(data));
  }
  inline void operator >> (bool& data){
     auto begin = reinterpret_cast<char*>(&data);
     memcpy(begin, mBuffer + mGetHead, sizeof(data));
     SeekG(mGetHead + sizeof(data));
     assert(mGetHead <= mPutHead);
  }

  inline void operator << (const char& data){
     CheckForCapacity(sizeof(data));

     auto begin = reinterpret_cast<const char*>(&data);
     memcpy(mBuffer + mPutHead, begin, sizeof(data));
     SeekP(mPutHead + sizeof(data));
  }
  inline void operator >> (char& data){
     auto begin = reinterpret_cast<char*>(&data);
     memcpy(begin, mBuffer + mGetHead, sizeof(data));
     SeekG(mGetHead + sizeof(data));
     assert(mGetHead <= mPutHead);
  }

  inline void operator << (const int& data){
     CheckForCapacity(sizeof(data));

     auto begin = reinterpret_cast<const char*>(&data);
     memcpy(mBuffer + mPutHead, begin, sizeof(data));
     SeekP(mPutHead + sizeof(data));
  }

  inline void operator >> (int& data){
     auto begin = reinterpret_cast<char*>(&data);
     memcpy(begin, mBuffer + mGetHead, sizeof(data));
	 SeekG(mGetHead + sizeof(data));
     assert(mGetHead <= mPutHead);

  }

  inline void operator << (const size_t& data){
     CheckForCapacity(sizeof(data));

     auto begin = reinterpret_cast<const char*>(&data);
     memcpy(mBuffer + mPutHead, begin, sizeof(data));
     SeekP(mPutHead + sizeof(data));
  }
  inline void operator >> (size_t& data){
     auto begin = reinterpret_cast<char*>(&data);
     memcpy(begin, mBuffer + mGetHead, sizeof(data));
	 SeekG(mGetHead + sizeof(data));
     if (mGetHead > mPutHead)
        assert(mGetHead <= mPutHead);
  }

  template <typename T>
  inline void operator >> (T& data){
     auto begin = reinterpret_cast<char*>(&data);
     memcpy(begin, mBuffer + mGetHead, sizeof(T));
     SeekG(mGetHead + sizeof(T));
     assert(mGetHead <= mPutHead);
  }

  template <typename T>
  inline void operator << (const T& data){
     CheckForCapacity(sizeof(T));
     auto begin = reinterpret_cast<const char*>(&data);
     memcpy(mBuffer + mPutHead, begin, sizeof(T));
     SeekP(mPutHead + sizeof(T));
  }

  inline void Read(void* dest, size_t length)
  {
     CheckForCapacity(length);
     memcpy(dest, mBuffer + mGetHead, length);
     SeekG(mGetHead + length);

     assert(mGetHead <= mPutHead);
  }

  inline void Write(const void* src, size_t length)
  {
     CheckForCapacity(length);
     memcpy(mBuffer + mPutHead, src, length);
     SeekP(mPutHead + length);
  }

  inline void WriteFromDevice(size_t i,std::unique_ptr<StorageDevice>& device, size_t length)
  {
     CheckForCapacity(length);
     device->PRead(i,mBuffer + mPutHead, length);
     SeekP(mPutHead + length);
  }

  size_t Getsize_tAtCurrentHeadG() {
     return *((size_t*)&mBuffer[mGetHead]);
  }

  inline char* HeadP() { return mBuffer + mPutHead; }
  inline char* HeadG() { return mBuffer + mGetHead; }

  inline size_t TellP() { return mPutHead; }
  inline size_t TellG() { return mGetHead; }

  void SeekP(size_t pos) {
  	mPutHead = pos; assert(mPutHead <= mCapacity);
  }
  inline void SeekG(size_t pos) {
  	mGetHead = pos; assert(mGetHead <= mCapacity);
  }

private:
  size_t mCapacity;
  size_t mPutHead;
  size_t mGetHead;

  char* mBuffer;
};

template <>
inline void BinaryStream::operator >> (std::string& data) {
  data = std::string(mBuffer + mGetHead, mBuffer + mPutHead);
  SeekG(mPutHead);
}

template <>
inline void BinaryStream::operator << (const std::string& data) {
  CheckForCapacity(data.size());
  memcpy(mBuffer + mPutHead, data.data(), data.size());
  SeekP(mPutHead + data.size());
}

#endif

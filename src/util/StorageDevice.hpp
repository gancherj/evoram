// Written by Peter

#ifndef COMMON_STORAGEDEVICE_HPP
#define COMMON_STORAGEDEVICE_HPP

#include "../common/Defines.hpp"

#include <boost/iostreams/device/mapped_file.hpp>
#include <boost/filesystem.hpp>

#include <fstream>
#include <vector>
#include <algorithm>
#include <initializer_list>
#include <cstddef>      // ptrdiff_t
#include <iterator>     // iterator
#include <type_traits>  // remove_cv
#include <utility>      // swap
#include <iostream>
#include <regex>



template<typename T>
T GetArg(std::istream& in, std::string expected)
{
  std::regex reg("\n? *" + expected + " *");
  std::string line;
  T out;
  getline(in, line, '=');

  if (regex_match(line, reg))
  {
     in >> out;
  }
  else {
     throw std::runtime_error("Invalid Ring ORAM State stream(" + expected + ")");
  }
  return out;
}

template <class BlockT>
class DeviceBlockWriteIterator;
template <class BlockT>
class DeviceBlockReadIterator;

class StorageDevice
{

public:

  StorageDevice(){};
  virtual ~StorageDevice(){};

  inline size_t Capacity() const
  {return CapacityImpl();}

  inline size_t Size() const
  {return SizeImpl();}

  inline size_t Read(void* data, size_t length)
  {return ReadImpl(data, length);}

  inline size_t Write(const void* data, size_t length)
  {return WriteImpl(data, length);}

  inline void SeekP(size_t byte)
  {SeekPImpl(byte);}

  inline void SeekG(size_t byte) const
  {return SeekGImpl(byte);}

  inline size_t TellP() const
  {return TellPImpl();}

  inline size_t TellG() const
  {return TellGImpl();}

  inline void Clear()
  {ClearImpl();}

  // Thread-safe interface

  inline bool ThreadSafeAvailable() const
  {return ThreadSafeAvailableImpl();}

  inline void PRead(size_t i, void* blocks, size_t n) const
  {PReadImpl(i, blocks, n);}

  inline void PWrite(size_t i, const void* blocks, size_t n)
  {PWriteImpl(i, blocks, n);}





  StorageDevice(const StorageDevice&) = delete;

  void operator=(const StorageDevice&) = delete;


private:

  virtual void ClearImpl() = 0;
  virtual size_t SizeImpl() const = 0;
  virtual size_t CapacityImpl() const = 0;
  virtual size_t ReadImpl(void* data, size_t length) const = 0;
  virtual size_t WriteImpl(const void* data, size_t length) = 0;
  virtual void SeekPImpl(size_t byte) = 0;
  virtual void SeekGImpl(size_t byte) const = 0;
  virtual size_t TellPImpl() const = 0;
  virtual size_t TellGImpl() const = 0;
  virtual bool ThreadSafeAvailableImpl() const = 0;
  virtual void PReadImpl(size_t i, void* blocks, size_t n) const = 0;
  virtual void PWriteImpl(size_t i, const void* blocks, size_t n) = 0;
};

template <typename BlockT>
class BlockStorageDevice : public StorageDevice
{
  static_assert(std::is_pod<BlockT>::value,
                "Template argument BlockT must be of type PODType in class template BlockStorageDevice");
  static_assert(std::is_standard_layout<BlockT>::value,
                "Template argument BlockT must be of type StandardLayoutType in class template BlockStorageDevice");
  static_assert(std::is_trivial<BlockT>::value,
                "Template argument BlockT must be of type TrivialType in class template BlockStorageDevice");
public:

  typedef DeviceBlockWriteIterator<BlockT> OutputIterator;
  typedef DeviceBlockReadIterator<BlockT> InputIterator;

  BlockStorageDevice():StorageDevice(){};//= default;
  virtual ~BlockStorageDevice() {};// = default;

  static inline size_t BytesPerBlock()
  {return sizeof(BlockT);}

  static inline size_t BlocksRequired(size_t byte_pos)
  {return IntDivCeil(byte_pos, BytesPerBlock());}

  // Thread-safe interface (add more methods if needed)


  inline void PReadBlocks(size_t i, BlockT* blocks, size_t n) const
  {PReadBlocksImpl(i, blocks, n);}

  inline void PWriteBlocks(size_t i, const BlockT* blocks, size_t n)
  {PWriteBlocksImpl(i, blocks, n);}

  inline void PReadBlock(size_t i, BlockT& block) const
  {PReadBlocksImpl(i, &block, 1);}

  inline void PWriteBlock(size_t i, const BlockT& block)
  {PWriteBlocksImpl(i, &block, 1);}

  //
  // Block-wise interface
  //

  inline DeviceBlockWriteIterator<BlockT> WriteBlockIter(size_t i)
  {return DeviceBlockWriteIterator<BlockT>(this, i);}

  inline DeviceBlockWriteIterator<BlockT> WriteBlockIterCurrent()
  {return WriteBlockIter(TellPBlock());}

  inline DeviceBlockWriteIterator<BlockT> WriteBlockIterEnd()
  {return DeviceBlockWriteIterator<BlockT>(this, SizeBlocks());}

  inline DeviceBlockReadIterator<BlockT> ReadBlockIter(size_t i)
  {return DeviceBlockReadIterator<BlockT>(this, i);}

  inline DeviceBlockReadIterator<BlockT> ReadBlockIterCurrent()
  {return ReadBlockIter(TellGBlock());}

  inline DeviceBlockReadIterator<BlockT> ReadBlockIterEnd()
  {return DeviceBlockReadIterator<BlockT>(this, SizeBlocks());}

  inline size_t SizeBlocks() const
  {return SizeBlocksImpl();}

  inline void ResizeBlocks(size_t i)
  {ResizeBlocksImpl(i);}

  inline void ReadBlock(size_t i, BlockT& block) const
  {ReadBlockImpl(i, block);}

  inline void ReadBlock(BlockT& block) const
  {ReadBlockImpl(TellGBlock(), block);}

  inline void WriteBlock(size_t i, const BlockT& block)
  {WriteBlockImpl(i, block);}

  inline void WriteBlock(const BlockT& block)
  {WriteBlockImpl(TellPBlock(), block);}

  inline void ReadBlocks(size_t i, BlockT* blocks, size_t n) const
  {ReadBlocksImpl(i, blocks, n);}

  inline void ReadBlocks(BlockT* blocks, size_t n) const
  {ReadBlocksImpl(TellGBlock(), blocks, n);}

  inline void WriteBlocks(size_t i, const BlockT* blocks, size_t n)
  {WriteBlocksImpl(i, blocks, n);}

  inline void WriteBlocks(const BlockT* blocks, size_t n)
  {WriteBlocksImpl(TellPBlock(), blocks, n);}

  inline const BlockT operator[](size_t i) const
  {BlockT tmp; ReadBlock(i, tmp); return tmp;}

  inline void SeekPBlock(size_t i)
  {SeekP(i * BytesPerBlock());}

  inline void SeekGBlock(size_t i) const
  {SeekG(i * BytesPerBlock());}

  inline size_t TellPBlock() const
  {return BlocksRequired(TellP());}

  inline size_t TellGBlock() const
  {return BlocksRequired(TellG());}

  //
  // Byte-wise interface
  //

  inline virtual size_t SizeImpl()  const override
  {return size_t(SizeBlocks()) * BytesPerBlock();}


  inline
  virtual size_t CapacityImpl() const override
  {return (size_t)-1;}


  BlockStorageDevice(const BlockStorageDevice&) = delete;

  void operator=(const BlockStorageDevice&) = delete;


private:


  virtual void PReadBlocksImpl(size_t i, BlockT* blocks, size_t n) const=0;
  virtual void PWriteBlocksImpl(size_t i, const BlockT* blocks, size_t n)=0;

  virtual size_t SizeBlocksImpl() const=0;
  virtual void ResizeBlocksImpl(size_t i)=0;
  virtual void ReadBlockImpl(size_t i, BlockT& block) const=0;
  virtual void WriteBlockImpl(size_t i, const BlockT& block)=0;
  virtual void ReadBlocksImpl(size_t i, BlockT* blocks, size_t n) const=0;
  virtual void WriteBlocksImpl(size_t i, const BlockT* blocks, size_t n)=0;
};

template <typename BlockT>
class FileBlockStorageDevice: public BlockStorageDevice<BlockT>
{
public:

  FileBlockStorageDevice(std::string storage_location,
                    bool exists=false)
     : BlockStorageDevice<BlockT>(),
       _storage_location(storage_location),
       _size(0)
  {
     _init(exists);
  }
  virtual ~FileBlockStorageDevice() {_f.close();}

  /** Default Constructor */
  FileBlockStorageDevice() = delete;
  /** Copy Constructor */
  FileBlockStorageDevice(const FileBlockStorageDevice&) = delete;
  /** Overloaded Equals Operator */
  void operator=(const FileBlockStorageDevice&) = delete;

private:

  void _init(bool exists)
  {
     if (!exists) {
        _f.open(_storage_location.c_str(),
                std::ios::in |
                std::ios::out |
                std::ios::binary |
                std::ios::trunc);
        AssertExit(_f.good() && _f.is_open(),
                   "Failed to open file stream");
        _size = 0;
     }
     else {
        _f.open(_storage_location.c_str(),
                std::ios::in |
                std::ios::out |
                std::ios::binary |
                std::ios::ate);
        AssertExit(_f.good(),
                   "Failed to reopen file stream");
        AssertExit(_f.is_open(),
                   "Failed to reopen file stream");
        _f.seekp(0, _f.end);
        size_t num_bytes = _f.tellp();
        _size = IntDivCeil(num_bytes,
                           BlockStorageDevice<BlockT>::BytesPerBlock());
        // we always guarantee untouched bytes
        // within blocks are initialized to zero
        if (num_bytes % BlockStorageDevice<BlockT>::BytesPerBlock()) {
           size_t extra_bytes =
              (num_bytes + BlockStorageDevice<BlockT>::BytesPerBlock())
            - (num_bytes % BlockStorageDevice<BlockT>::BytesPerBlock())
            - 1;
           std::unique_ptr<char> zeros(new char[extra_bytes]);
           std::fill_n(zeros.get(), extra_bytes, 0);
           WriteImpl(zeros.get(), extra_bytes);
        }
        _f.seekp(num_bytes);
     }
  }

  inline
  virtual void ClearImpl() override
  {_init(false);}

  inline
  virtual bool ThreadSafeAvailableImpl() const override
  {return false;} // This could be done on Unix using pread/pwrite

  inline
  virtual void PReadBlocksImpl(size_t i, BlockT* blocks, size_t n) const
  {throw std::runtime_error("FileBlockStorageDevice::PReadBlocks: Interface not available.");}

  inline
  virtual void PWriteBlocksImpl(size_t i, const BlockT* blocks, size_t n) override
  {throw std::runtime_error("FileBlockStorageDevice::PWriteBlocks: Interface not available.");}

  inline
  virtual void PReadImpl(size_t i, void* blocks, size_t n) const
  {throw std::runtime_error("FileBlockStorageDevice::PRead: Interface not available.");}

  inline
  virtual void PWriteImpl(size_t i, const void* blocks, size_t n) override
  {throw std::runtime_error("FileBlockStorageDevice::PWrite: Interface not available.");}


  inline
  virtual size_t ReadImpl(void* data, size_t length) const override
  {assert(data); _f.read(reinterpret_cast<char*>(data), length); assert(_f.good()); return _f.gcount();}

  inline
  virtual size_t WriteImpl(const void* data, size_t length) override
  {assert(data); _f.write(reinterpret_cast<const char*>(data), length); assert(_f.good()); return (_f.good())?(length):(0);}

  inline
  virtual void SeekPImpl(size_t byte) override
  {_f.seekp(byte);}

  inline
  virtual void SeekGImpl(size_t byte) const override
  {_f.seekg(byte);}

  inline
  virtual size_t TellPImpl() const override
  {return _f.tellp();}

  inline
  virtual size_t TellGImpl() const override
  {return _f.tellg();}

  inline
  virtual size_t SizeBlocksImpl() const override
  {return _size;}

  virtual void ResizeBlocksImpl(size_t i) override
  {
     if (i <= _size) {
        _f.close();
        _size = i;
        boost::filesystem::resize_file(_storage_location, _size * BlockStorageDevice<BlockT>::BytesPerBlock());
        _init(true);
     }
     else {
        // assumed POD
        // *Nevermind: Fix for stupid Visual Studio compiler
        std::vector<unsigned char> zero(sizeof(BlockT), 0);
        const BlockT& zero_block = *((BlockT*)zero.data());
        for (size_t k = _size; k < _size; ++k) {
           WriteBlockImpl(k, zero_block);
        }
        _size = i;
     }
  }

  inline
  virtual void ReadBlockImpl(size_t i, BlockT& block) const override
  {_f.seekg(i * BlockStorageDevice<BlockT>::BytesPerBlock()); _f.read(reinterpret_cast<char*>(&block), BlockStorageDevice<BlockT>::BytesPerBlock());}

  inline
  virtual void WriteBlockImpl(size_t i, const BlockT& block) override
  {_f.seekp(i * BlockStorageDevice<BlockT>::BytesPerBlock()); _f.write(reinterpret_cast<const char*>(&block), BlockStorageDevice<BlockT>::BytesPerBlock());}

  inline
  virtual void ReadBlocksImpl(size_t i, BlockT* blocks, size_t n) const override
  {assert(blocks); _f.seekg(i * BlockStorageDevice<BlockT>::BytesPerBlock()); _f.read(reinterpret_cast<char*>(blocks), BlockStorageDevice<BlockT>::BytesPerBlock() * n);}

  inline
  virtual void WriteBlocksImpl(size_t i, const BlockT* blocks, size_t n) override
  {assert(blocks); _f.seekp(i * BlockStorageDevice<BlockT>::BytesPerBlock()); _f.write(reinterpret_cast<const char*>(blocks), BlockStorageDevice<BlockT>::BytesPerBlock() * n);}

  mutable std::fstream _f;
  std::string _storage_location;
  size_t _size;
};

template <typename BlockT>
class RAMBlockStorageDevice: public BlockStorageDevice<BlockT>
{
public:

  RAMBlockStorageDevice()
     : BlockStorageDevice<BlockT>(),
     _v(),
     _get_byte(0),
     _put_byte(0)
  {}
  RAMBlockStorageDevice(size_t size)
     : BlockStorageDevice<BlockT>(),
     _v(size),
     _get_byte(0),
     _put_byte(0)
  {}
  RAMBlockStorageDevice(std::initializer_list<BlockT> init)
     : BlockStorageDevice<BlockT>(),
     _v(init),
     _get_byte(0),
     _put_byte(0)
  {
     _put_byte = BlockStorageDevice<BlockT>::Size();
  }
  template <class InputIterator>
  RAMBlockStorageDevice(InputIterator f, InputIterator l)
     : BlockStorageDevice<BlockT>(),
     _v(),
     _get_byte(0),
     _put_byte(0)
  {
     _v.insert(_v.begin(), f, l);
     _put_byte = BlockStorageDevice<BlockT>::Size();
  }
  virtual ~RAMBlockStorageDevice() = default;

  std::vector<BlockT>& vector()
  {return _v;}
  const std::vector<BlockT>& vector() const
  {return _v;}

  inline const BlockT& operator[](size_t i) const
  {BlockStorageDevice<BlockT>::SeekGBlock(i+1); return _v[i];}

  inline const BlockT& at(size_t i) const
  {return this->operator[](i);}

  inline const BlockT* data() const
  {return _v.data();}

  inline BlockT* data()
  {return _v.data();}

  /** Default Constructor */
  //RAMBlockStorageDevice() = delete;
  /** Copy Constructor */
  RAMBlockStorageDevice(const RAMBlockStorageDevice&) = delete;
  /** Overloaded Equals Operator */
  void operator=(const RAMBlockStorageDevice&) = delete;

private:

  inline
  virtual void ClearImpl() override
  {_v.clear(); std::vector<BlockT>().swap(_v);}

  inline
  virtual bool ThreadSafeAvailableImpl() const override
  {return true;}

  inline
  virtual void PReadBlocksImpl(size_t i, BlockT* blocks, size_t n) const
  {assert(blocks); memcpy(blocks, _v.data() + i, BlockStorageDevice<BlockT>::BytesPerBlock() * n);}

  inline
  virtual void PWriteBlocksImpl(size_t i, const BlockT* blocks, size_t n) override
  {assert(blocks); memcpy(_v.data() + i, blocks, BlockStorageDevice<BlockT>::BytesPerBlock() * n);}

  inline
  virtual void PReadImpl(size_t i, void* dest, size_t n) const
  {assert(dest); memcpy(reinterpret_cast<char*>(dest), reinterpret_cast<const char*>(_v.data()) + i, n);}

  inline
  virtual void PWriteImpl(size_t i, const void* src, size_t n) override
  {assert(src); memcpy(reinterpret_cast<char*>(_v.data()) + i, reinterpret_cast<const char*>(src), n);}

  inline
  virtual size_t ReadImpl(void* data, size_t length) const override
  {
     assert(_get_byte < BlockStorageDevice<BlockT>::Size());
     assert(_get_byte + length <= BlockStorageDevice<BlockT>::Size());
     assert(data);
     memcpy(data, reinterpret_cast<const char*>(_v.data()) + _get_byte, length); _get_byte += length;
     return (_get_byte <= BlockStorageDevice<BlockT>::Size())?(length):(0);
  }

  // allow the vector to grow dynamically
  virtual size_t WriteImpl(const void* data, size_t length) override
  {
     if ((_put_byte >= BlockStorageDevice<BlockT>::Size()) ||
         (_put_byte + length > BlockStorageDevice<BlockT>::Size())) {
        size_t put_byte_orig = _put_byte;
        _put_byte += length + 1;


        _v.resize(BlockStorageDevice<BlockT>::TellPBlock());

        _v.resize(_v.capacity());
        _put_byte = put_byte_orig;
     }
     assert(_put_byte < BlockStorageDevice<BlockT>::Size());
     assert(_put_byte + length <= BlockStorageDevice<BlockT>::Size());
     assert(data);
     memcpy(reinterpret_cast<char*>(_v.data()) + _put_byte, data, length);
     _put_byte += length;
     return (_put_byte <= BlockStorageDevice<BlockT>::Size())?(length):(0);
  }

  inline
  virtual void SeekPImpl(size_t byte) override
  {_put_byte = byte;}

  inline
  virtual void SeekGImpl(size_t byte) const override
  {_get_byte = byte;}

  inline
  virtual size_t TellPImpl() const override
  {return _put_byte;}

  inline
  virtual size_t TellGImpl() const override
  {return _get_byte;}

  inline
  virtual size_t SizeBlocksImpl() const override
  {return _v.size();}

  inline
  virtual void ResizeBlocksImpl(size_t i) override
  {_v.resize(i);}

  inline
  virtual void ReadBlockImpl(size_t i, BlockT& block) const override
  {block = this->operator[](i);}

  inline
  virtual void WriteBlockImpl(size_t i, const BlockT& block) override
  {_v[i] = block; BlockStorageDevice<BlockT>::SeekPBlock(i+1);}

  inline
  virtual void ReadBlocksImpl(size_t i, BlockT* blocks, size_t n) const override
  {assert(blocks); memcpy(blocks, _v.data() + i, BlockStorageDevice<BlockT>::BytesPerBlock() * n); BlockStorageDevice<BlockT>::SeekGBlock(i+n);}

  inline
  virtual void WriteBlocksImpl(size_t i, const BlockT* blocks, size_t n) override
  {assert(blocks); memcpy(_v.data() + i, blocks, BlockStorageDevice<BlockT>::BytesPerBlock() * n); BlockStorageDevice<BlockT>::SeekPBlock(i+n);}

  std::vector<BlockT> _v;
  mutable size_t _get_byte;
  size_t _put_byte;
};

template <typename BlockT>
class MMFileBlockStorageDevice: public BlockStorageDevice<BlockT>
{
public:

  MMFileBlockStorageDevice(std::string storage_location, size_t size, bool exists=false)
     : BlockStorageDevice<BlockT>(),
       _storage_location(storage_location),
       _size(0),
       _get_byte(0),
       _put_byte(0)
  {
     _init(exists, size);
  }
  virtual ~MMFileBlockStorageDevice() {_f.close();}

  inline const BlockT& operator[](size_t i) const
  {BlockStorageDevice<BlockT>::SeekGBlock(i+1); return reinterpret_cast<const
      BlockT*>(_f.const_data())[i];}

  inline const BlockT& at(size_t i) const
  {return this->operator[](i);}

  inline const BlockT* data() const
  {return reinterpret_cast<const BlockT*>(_f.data());}

  inline BlockT* data()
  {return reinterpret_cast<BlockT*>(_f.data());}



  /** Default Constructor */
  MMFileBlockStorageDevice() = delete;
  /** Copy Constructor */
  MMFileBlockStorageDevice(const MMFileBlockStorageDevice&) = delete;
  /** Overloaded Equals Operator */
  void operator=(const MMFileBlockStorageDevice&) = delete;

private:
  // ---member variables---
  // the file stream object
  boost::iostreams::mapped_file _f;

  // location of file
  std::string _storage_location;

  // size of a block
  size_t _size;

  // counters use for when we access data like we use a binary stream
  // server.cpp never uses methods that use _get_byte or _put_byte
  // to work with the data
  mutable size_t _get_byte;
  size_t _put_byte;

  void _init(bool exists, size_t size)
  {
     if ( !boost::filesystem::exists( _storage_location ) )
     {
        std::fstream tmp;
        tmp.open(_storage_location.c_str(),
                 std::ios::out |
                 std::ios::in |
                 std::ios::binary |
                 std::ios::trunc);
        AssertExit(tmp.is_open(),
                   "Failed to open file stream");
        AssertExit(tmp.is_open(),
                   "Failed to open file stream");
        char tmp_char = 0;
        tmp.write(&tmp_char, sizeof(char));
        tmp.close();
        _size = 0;
     }

     boost::iostreams::mapped_file_params  params;
     params.path = _storage_location;
     params.mode = (std::ios_base::out | std::ios_base::in);
     params.new_file_size = size;
     _f.open(params);
     AssertExit(_f.is_open(),
                "Failed to open file stream");

     size_t num_bytes = _f.size();
     _size = IntDivCeil(num_bytes,
                        BlockStorageDevice<BlockT>::BytesPerBlock());
     // we always guarantee untouched bytes
     // within blocks are initialized to zero
     if (num_bytes % BlockStorageDevice<BlockT>::BytesPerBlock()) {
        size_t extra_bytes =
           (num_bytes + BlockStorageDevice<BlockT>::BytesPerBlock())
         - (num_bytes % BlockStorageDevice<BlockT>::BytesPerBlock())
         - 1;
        std::unique_ptr<char> zeros(new char[extra_bytes]);
        std::fill_n(zeros.get(), extra_bytes, 0);
        WriteImpl(zeros.get(), extra_bytes);
     }
     _put_byte = num_bytes;
     _get_byte = 0;

  }

  inline
  virtual void ClearImpl() override
  {
     this->_f.close();
     //_init(false);
  }

  inline
  virtual bool ThreadSafeAvailableImpl() const override
  {return true;}

  inline
  virtual void PReadBlocksImpl(size_t i, BlockT* blocks, size_t n) const
  {assert(blocks); memcpy(blocks, reinterpret_cast<const BlockT*>(_f.data()) + i, BlockStorageDevice<BlockT>::BytesPerBlock() * n);}

  inline
  virtual void PWriteBlocksImpl(size_t i, const BlockT* blocks, size_t n) override
  {
     assert(blocks);
     throw std::runtime_error("not implemented");

     // memcpy(reinterpret_cast<BlockT*>(_f.data()), blocks, BlockStorageDevice<BlockT>::BytesPerBlock() * n);
     // memcpy(reinterpret_cast<BlockT*>(_f.data()) + i, blocks, BlockStorageDevice<BlockT>::BytesPerBlock() * n);
  }

  inline
  virtual void PReadImpl(size_t i, void* dest, size_t n) const
  {
     /// Read using memcpy(dest, _f.data()+i, n)
     assert(dest);
     memcpy(reinterpret_cast<char*>(dest), reinterpret_cast<char*>(_f.data()) + i, n);
  }

  inline
  virtual void PWriteImpl(size_t i, const void* src, size_t n) override
  {
     ///std::cout << "MMFileBlockStorageDevice::PWriteImpl writing, i=" << i << std::endl;
     /// Write using memcpy(_f.data()+i, src, n)
     assert(src);
     memcpy(reinterpret_cast<char*>(_f.data()) + i, reinterpret_cast<const char*>(src), n);
  }

  inline
  virtual size_t ReadImpl(void* data, size_t length) const override
  {
     /// _get_byte and _put_byte seem to use the same type of procedure
     /// as binary stream, but implemented on top of a StorageDevice.
     /// memcpy(data, _f.data() + _get_byte, length)
     /// and then incrememnt _get_byte appropriately
     assert(_get_byte < BlockStorageDevice<BlockT>::Size());
     assert(_get_byte + length <= BlockStorageDevice<BlockT>::Size());
     assert(data);
     memcpy(data, _f.data() + _get_byte, length);
     _get_byte += length;
     return (_get_byte <= BlockStorageDevice<BlockT>::Size())?(length):(0);
  }

  inline
  virtual size_t WriteImpl(const void* data, size_t length) override
  {
     /// _get_byte and _put_byte seem to use the same type of procedure
     /// as binary stream, but implemented on top of a StorageDevice.
     /// memcpy(_f.data() + _put_byte, data, length)
     /// and then incrememnt _put_byte appropriately
     assert(_put_byte < BlockStorageDevice<BlockT>::Size());
     assert(_put_byte + length <= BlockStorageDevice<BlockT>::Size());
     assert(data);
     memcpy(_f.data() + _put_byte, data, length);
     _put_byte += length;
     return (_put_byte <= BlockStorageDevice<BlockT>::Size())?(length):(0);
  }

  inline
  virtual void SeekPImpl(size_t byte) override
  {_put_byte = byte;}

  inline
  virtual size_t TellPImpl() const override
  {return _put_byte;}

  inline
  virtual void SeekGImpl(size_t byte) const override
  {_get_byte = byte;}

  inline
  virtual size_t TellGImpl() const override
  {return _get_byte;}

  inline
  virtual size_t SizeBlocksImpl() const override
  {return _size;}

  virtual void ResizeBlocksImpl(size_t i) override
  {
     if (!_f.is_open()) {
        assert(_size == 0);
        boost::iostreams::mapped_file_params  params;
        params.path = _storage_location;
        params.new_file_size = i * BlockStorageDevice<BlockT>::BytesPerBlock();
        params.mode = (std::ios_base::out | std::ios_base::in);
        _f.open(params);
        AssertExit(_f.is_open(),
                   "Failed to open file stream");
        _size = i;
     }
     if (i <= _size) {
        _f.close();
        _size = i;
        boost::filesystem::resize_file(_storage_location, _size * BlockStorageDevice<BlockT>::BytesPerBlock());
        _init(true, _size);
     }
     else {
        _f.close();
        boost::iostreams::mapped_file_params  params;
        params.path = _storage_location;
        params.length = i * BlockStorageDevice<BlockT>::BytesPerBlock();
        params.mode = (std::ios_base::out | std::ios_base::in);
        _f.open(params);
        AssertExit(_f.is_open(),
                   "Failed to open file stream");
        // assumed POD
        // *Nevermind: Fix for stupid Visual Studio compiler
        std::vector<unsigned char> zero(sizeof(BlockT), 0);
        const BlockT& zero_block = *((BlockT*)zero.data());
        for (size_t k = _size; k < _size; ++k) {
           WriteBlockImpl(k, zero_block);
        }
        _size = i;
     }
  }

  inline
  virtual void ReadBlockImpl(size_t i, BlockT& block) const override
  {block = this->operator[](i);}

  inline
  virtual void WriteBlockImpl(size_t i, const BlockT& block) override
  {reinterpret_cast<BlockT*>(_f.data())[i] = block; BlockStorageDevice<BlockT>::SeekPBlock(i+1);}

  inline
  virtual void ReadBlocksImpl(size_t i, BlockT* blocks, size_t n) const override
  {assert(blocks); memcpy(blocks, reinterpret_cast<const BlockT*>(_f.data()) + i, BlockStorageDevice<BlockT>::BytesPerBlock() * n); BlockStorageDevice<BlockT>::SeekGBlock(i+n);}

  inline
  virtual void WriteBlocksImpl(size_t i, const BlockT* blocks, size_t n) override
  {assert(blocks); memcpy(reinterpret_cast<BlockT*>(_f.data()) + i, blocks, BlockStorageDevice<BlockT>::BytesPerBlock() * n); BlockStorageDevice<BlockT>::SeekPBlock(i+n);}
};

template <class BlockT>
class DeviceBlockWriteIterator
  : public std::iterator<std::output_iterator_tag, void, void, void, void>
{
private:

  BlockStorageDevice<BlockT>* _dev;
  size_t _block_pos;

public:

  DeviceBlockWriteIterator()
     : _dev(nullptr),
       _block_pos(0)
  {}

  explicit DeviceBlockWriteIterator(BlockStorageDevice<BlockT>* dev, size_t block_pos)
     : _dev(dev),
       _block_pos(block_pos)
  {}

  DeviceBlockWriteIterator& operator=(const BlockT& rhs)
  {
     assert(_dev != nullptr && "Invalid iterator!");
     _dev->WriteBlock(_block_pos, rhs);
     return *this;
  }

  void swap(DeviceBlockWriteIterator& other) /*noexcept*/
  {
     using std::swap;
     swap(_dev, other._dev);
     swap(_block_pos, other._block_pos);
  }

  DeviceBlockWriteIterator& operator++ () // Pre-increment
  {
     ++_block_pos;
     return *this;
  }

  DeviceBlockWriteIterator operator++ (int) // Post-increment
  {
     DeviceBlockWriteIterator tmp(_dev, _block_pos++);
     return tmp;
  }

  // two-way comparison: v.begin() == v.cbegin() and vice versa
  template<class OtherType>
  bool operator == (const DeviceBlockWriteIterator<OtherType>& rhs) const
  {
     return (_dev == rhs._dev) && (_block_pos == rhs._block_pos);
  }

  template<class OtherType>
  bool operator != (const DeviceBlockWriteIterator<OtherType>& rhs) const
  {
     return (_dev != rhs._dev) || (_block_pos != rhs._block_pos);
  }

  DeviceBlockWriteIterator& operator* ()
  {
     return *this;
  }
};

template <class BlockT>
class DeviceBlockReadIterator
  : public std::iterator<std::input_iterator_tag, void, void, void, void>
{
private:

  BlockStorageDevice<BlockT>* _dev;
  size_t _block_pos;

public:

  DeviceBlockReadIterator()
     : _dev(nullptr),
       _block_pos(0)
  {}

  explicit DeviceBlockReadIterator(BlockStorageDevice<BlockT>* dev, size_t block_pos)
     : _dev(dev),
       _block_pos(block_pos)
  {}

  void swap(DeviceBlockReadIterator& other) /*
                                */
  {
     using std::swap;
     swap(_dev, other._dev);
     swap(_block_pos, other._block_pos);
  }

  DeviceBlockReadIterator& operator++ () // Pre-increment
  {
     ++_block_pos;
     return *this;
  }

  DeviceBlockReadIterator operator++ (int) // Post-increment
  {
     DeviceBlockReadIterator tmp(_dev, _block_pos++);
     return tmp;
  }

  // two-way comparison: v.begin() == v.cbegin() and vice versa
  template<class OtherType>
  bool operator == (const DeviceBlockReadIterator<OtherType>& rhs) const
  {
     return (_dev == rhs._dev) && (_block_pos == rhs._block_pos);
  }

  template<class OtherType>
  bool operator != (const DeviceBlockReadIterator<OtherType>& rhs) const
  {
     return (_dev != rhs._dev) || (_block_pos != rhs._block_pos);
  }

  BlockT operator* () const
  {
     assert(_dev != nullptr && "Invalid iterator!");
     return std::move((*_dev)[_block_pos]);
  }
};

#endif

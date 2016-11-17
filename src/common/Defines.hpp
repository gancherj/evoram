#ifndef DSE_COMMON_DEFINES
#define DSE_COMMON_DEFINES

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// #include <algorithm>
#include <memory>
#include <cstddef>
#include <iostream>
#include <cstdint>
#include "Constants.hpp"
#include "../Crypto/Crypto.hpp"
#include <thread>
#include <chrono>
#include <list>

inline void AssertExit(bool test, const char* message)
{
    if(!test)
    {
        std::cout<<message<<std::endl;
        exit(-1);
    }
    return;
}

inline size_t IntDivCeil(size_t i, size_t j)
{
    if (i % j)
    {
        return i / j + 1;
    }
    else
    {
        return i / j;
    }
}

namespace Path {
    namespace Malicious {
        enum class Operation : char {
            Read,
            Write,
        };

        enum class Command : char {
            LoadState,
            SaveState,
            DummyFill,
            ReadPath,
            WritePath, //only above are important

            CloseChannel,
            Terminate,
            Blocksize,
        };
    }

    namespace Verifiable {
        enum class Operation : char {
            Read,
            Write,
        };

        enum class Command : char {
            LoadState,
            SaveState,
            DummyFill,
            ReadPath,
            InitialClientSig,
            SigExchange,
            ContractHandshake,
            VerifyRequest,
            WritePath, //only above are important

            CloseChannel,
            Terminate,
            Blocksize,
            LeafRequest, // for C verifier
        };
    }
}

   class Block
   {
      public:
         Block() {
            memset (data, '\0', data_size);
         }

         static const size_t data_size = BLOCK_DATA_SIZE;
         char data[data_size];
   };

   class PathBlock {
   public:
      PathBlock() {
         memset (data, '\0', data_size);
      }

      static const size_t data_size = BLOCK_DATA_SIZE - sizeof(size_t);
      char data[data_size];
  };

   class EncryptedBlock
   {
      public:
         static const size_t data_size = AES::BLOCKSIZE + AES::BLOCKSIZE *
            ((BLOCK_DATA_SIZE) / AES::BLOCKSIZE); //hardcoded computation of encryption size of Block
         static const size_t iv_size = Crypto::BlockSize;
         char data[data_size];
         byte iv[iv_size];
   };

#endif

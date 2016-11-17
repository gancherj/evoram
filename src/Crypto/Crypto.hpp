#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/eccrypto.h>
#include "../ethincludes/SHA3.h"
#include <cryptopp/oids.h>
#include <cryptopp/sha3.h>

#include <cstring>
#include <iostream>
#include <algorithm>
#include <string.h>
#include <tuple>
#include <vector>

using byte = uint8_t;

struct sBytes64 {
    char data[64];
};

using bytes64 = sBytes64;
using namespace CryptoPP;

namespace Crypto
{
   const size_t KeySize = AES::DEFAULT_KEYLENGTH;
   const size_t BlockSize = AES::BLOCKSIZE;
   void MakeKey(SecByteBlock& key);
   void MakeIV(byte* iv);
   void AESEncrypt (SecByteBlock* key, byte* iv, const void* data, size_t length, std::string& dest);
   void AESDecrypt (SecByteBlock* key, byte* iv, std::string& ciphertext, void* dest, size_t length);
   size_t GetEncryptionSize (size_t input_size);
   size_t GetRandomSize_t();
   size_t GetRandomLessThan(size_t modulus);

   std::string SHA3 (const void* src, size_t length);
   std::string SHA3 (std::string in);

   std::string ToHex(std::string in);
   std::string ToHex(void* src, size_t length);

   std::vector<byte> FromHex(std::string in);

   namespace ECCSig {
       using CryptoPP::ECDSA;
       typedef ECDSA<ECP, SHA3_256>::PublicKey ECDSA_PubKey;
       typedef ECDSA<ECP, SHA3_256>::PrivateKey ECDSA_PrivKey;

       const size_t SIGSIZE = 64;
       
       struct ECDSA_HexSignature {
           std::string r;
           std::string s;
       };



       std::string pk_to_addr(ECDSA_PubKey pub);

       std::string pk_to_hex(ECDSA_PubKey pub);
       std::string sk_to_hex(ECDSA_PrivKey priv);

       ECDSA_HexSignature Sign(ECDSA_PrivKey priv, std::string msg);
       bool Verify(ECDSA_PubKey pk, std::string msg, ECDSA_HexSignature sig);
       ECDSA_HexSignature ParseSignature(bytes64 in);
       bytes64 SerializeSignature(ECDSA_HexSignature in);


       void WritePrivKeyToFile(ECDSA_PrivKey priv, std::string filename);
       void WritePubKeyToFile(ECDSA_PubKey pub, std::string filename);

       ECDSA_PrivKey LoadPrivKeyFromFile(std::string filename);
       ECDSA_PubKey LoadPubKeyFromFile(std::string filename);

       ECDSA_PrivKey GenFreshPrivKey();
       ECDSA_PubKey PrivToPubKey(ECDSA_PrivKey priv);
   }

};
#endif

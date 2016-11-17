#include "Crypto.hpp"
#include <fstream>

using namespace CryptoPP;
namespace Crypto {
void MakeKey(SecByteBlock& key)
{
   //expects SecByteBlock key
   if (key.empty())
   {
      key.Grow(KeySize);
   }
   AutoSeededRandomPool rng; //this pulls from /dev/random on unix machines
   rng.GenerateBlock(key, key.size());
   return;
}


void MakeIV(byte* iv)
{
   AutoSeededRandomPool rng; //this pulls from /dev/random on unix machines
   rng.GenerateBlock(iv, BlockSize);
   return;
}

void AESEncrypt (SecByteBlock* key, byte* iv, const void* data, size_t length, std::string& dest)
{
   CBC_Mode<AES>::Encryption enc(*key, key->size(), iv);

   StringSource sse((unsigned char*)data, length,
      true,
      new StreamTransformationFilter(
         enc,
         new StringSink(dest)));

}

void AESDecrypt (SecByteBlock* key, byte* iv, std::string& ciphertext, void* dest, size_t length)
{

   CBC_Mode<AES>::Decryption dec(*key, key->size(), iv);

   StringSource ssd(ciphertext,
      true,
      new StreamTransformationFilter(
         dec,
         new ArraySink((unsigned char*)dest, length)));
}

size_t GetEncryptionSize (size_t input_size)
{
   //Size of std::string output of AESEncrypt

   return AES::BLOCKSIZE + AES::BLOCKSIZE * (input_size / AES::BLOCKSIZE);
}

std::string SHA3 (const void* src, size_t length) {
    return std::string((const char*)dev::sha3(std::string((const char*)src, length)).data(), 32); //sha3_256 is 32 bytes long
}

std::string SHA3 (std::string in) {
    return std::string((const char*)dev::sha3(in).data(), 32);
}

size_t GetRandomSize_t()
{
   AutoSeededRandomPool rng;
   size_t out;
   rng.GenerateBlock(reinterpret_cast<byte*>(&out), sizeof(size_t));
   return out;
}

size_t GetRandomLessThan(size_t modulus)
{
   return GetRandomSize_t() % modulus;
}

std::string ToHex(std::string in) {
    return dev::toHex(in);
}

std::string ToHex(void* src, size_t len) {
    return ToHex(std::string((const char*)src, len));
}

std::vector<byte> FromHex(std::string in) {
    return dev::fromHex(in);
}

namespace ECCSig {

std::string pk_to_addr(ECDSA_PubKey pub) {
    CryptoPP::Integer r = pub.GetPublicElement().x;
    CryptoPP::Integer s = pub.GetPublicElement().y;

    char pk[64];
    r.Encode((byte*)pk, 32);
    s.Encode((byte*)pk + 32, 32);

    std::string pubhash = SHA3(pk, 64);
    return ToHex(pubhash.substr(12, 20));
}

std::string pk_to_hex(ECDSA_PubKey pub) {
    CryptoPP::Integer r = pub.GetPublicElement().x;
    CryptoPP::Integer s = pub.GetPublicElement().y;

    char pk[64];
    r.Encode((byte*)pk, 32);
    s.Encode((byte*)pk + 32, 32);
    return ToHex(std::string(pk, 64));
}

std::string sk_to_hex(ECDSA_PrivKey priv) {
    CryptoPP::Integer k = priv.GetPrivateExponent();

    char sk[32];
    k.Encode((byte*)sk, 32);
    return ToHex(std::string(sk, 32));
}

ECDSA_HexSignature Sign(ECDSA_PrivKey priv, std::string msg) {
    AutoSeededRandomPool prng;
    std::string sig;
    StringSource( msg, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA3_256>::Signer(priv),
            new StringSink( sig )
        ) // SignerFilter
    ); // StringSource

    std::string hex = ToHex(sig);
    return {hex.substr(0, 64), hex.substr(64, 64)};

}

bool Verify(ECDSA_PubKey pk, std::string msg, ECDSA_HexSignature sighex) {
    std::string sig(SerializeSignature(sighex).data, 64);
    bool result = false;
    StringSource ss( sig+msg, true /*pump all*/,
    new SignatureVerificationFilter(
        ECDSA<ECP,SHA3_256>::Verifier(pk),
        new ArraySink( (byte*)&result, sizeof(result) )
    ) // SignatureVerificationFilter
    );

    return result;
}

ECDSA_HexSignature ParseSignature(bytes64 in) {
    std::string d(in.data, 64);
    std::string hex = ToHex(d);
    return {hex.substr(0, 64), hex.substr(64, 64)};
}

bytes64 SerializeSignature(ECDSA_HexSignature in) {
    std::string h = in.r + in.s;
    assert(h.size() == 128);
    std::vector<byte> data = FromHex(h);
    bytes64 out;
    memcpy(out.data, data.data(), 64);
    return out;
}

void WritePrivKeyToFile(ECDSA_PrivKey priv, std::string filename) {
    std::string hex = sk_to_hex(priv);
    std::ofstream ofs(filename, std::ofstream::out);
    ofs<<hex;
    ofs.close();
}

void WritePubKeyToFile(ECDSA_PubKey pub, std::string filename) {
    std::string hex = pk_to_hex(pub);
    std::ofstream ofs(filename, std::ofstream::out);
    ofs<<hex;
    ofs.close();
}

ECDSA_PubKey LoadPubKeyFromFile(std::string filename) {
    std::ifstream ifs(filename);
    std::string hex( (std::istreambuf_iterator<char>(ifs) ),
                       (std::istreambuf_iterator<char>()    ) );
    ifs.close();
    std::vector<byte> key = FromHex(hex);
    ECP::Point q;
    q.identity = false;
    q.x.Decode(key.data(), 32);
    q.y.Decode(key.data() + 32, 32);

    ECDSA_PubKey out;
    out.Initialize(CryptoPP::ASN1::secp256k1(), q);
    return out;
}

ECDSA_PrivKey LoadPrivKeyFromFile(std::string filename) {
    std::ifstream ifs(filename);
    std::string hex( (std::istreambuf_iterator<char>(ifs) ),
                       (std::istreambuf_iterator<char>()    ) );
    ifs.close();

    std::vector<byte> key = FromHex(hex);
    Integer k;
    k.Decode(key.data(), 32);

    ECDSA_PrivKey out;
    out.Initialize(CryptoPP::ASN1::secp256k1(), k);
    return out;
}

ECDSA_PrivKey GenFreshPrivKey() {
    ECDSA_PrivKey out;
    AutoSeededRandomPool prng;
    out.Initialize( prng, CryptoPP::ASN1::secp256k1() );
    return out;
}

ECDSA_PubKey PrivToPubKey(ECDSA_PrivKey priv) {
    ECDSA_PubKey out;
    priv.MakePublicKey(out);
    return out;
}
}
}

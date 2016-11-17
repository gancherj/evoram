#ifndef MYABI_HPP
#define MYABI_HPP
#include <string>
#include <vector>
#include "../Crypto/Crypto.hpp"

namespace Abi {


// REFACTOR: make ValueType contain just two things: a std::string for values, and a std::vector<std::string> for arrays. All in binary (not hex). Then encode / decode at will.

// copy ToHex / FromHex from crypto into here
struct ValueType { // hack to do a sum type in C
    static ValueType String(std::string s) {
        ValueType out;
        out.str = s;
        return out;
    }
    static ValueType String(byte* bs, size_t len) {
        ValueType out;
        out.str = std::string((char*)bs, len);
        return out;
    }
    static ValueType Int(int i) {
        ValueType out;
        out.signed_int = i;
        return out;
    }
    static ValueType Uint(unsigned int i) {
        ValueType out;
        out.unsigned_int = i;
        return out;
    }
    static ValueType Bool(bool b) {
        ValueType out;
        out.boolean = b;
        return out;
    }

    std::string str;
    unsigned int unsigned_int;
    int signed_int;
    bool boolean;
    std::vector<std::string> bytearr;
    std::vector<unsigned int> uintarr;
    std::vector<int> intarr;
    std::vector<bool> boolarr;
};

bool is_dynamic(std::string type);
bool is_static(std::string type);
namespace Encode {
    std::string padleft(std::string in);

    std::string padright(std::string in);

    std::string encode_uint(unsigned int i);

    std::string encode_bytes32_arr(std::vector<std::string> in);
    std::string encode_uint_arr(std::vector<unsigned int> in);

    std::string encode_bytes(std::string in);
    std::string encode_call(std::string fun_sig, std::vector<std::string> types, std::vector<ValueType> values);

}

namespace Decode {
    std::string decode_bytes32(std::string data);
    unsigned int decode_uint(std::string data);
    bool decode_bool(std::string data);
    std::string decode_bytes(std::string data);
    std::vector<std::string> decode_bytes32arr(std::string data);
    std::string decode_address(std::string data);
    std::vector<bool> decode_boolarr(std::string data);
    std::vector<unsigned int> decode_uint256arr(std::string data);

    ValueType decode_static(std::string type, std::string data);
    ValueType decode_dynamic(std::string type, std::string data);
    std::vector<ValueType> decode_data(std::vector<std::string> types, std::string data);
}

}
#endif

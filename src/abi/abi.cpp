#include <string>
#include <vector>
#include "abi.hpp"
#include <sstream>
#include <ios>
#include <iostream>
#include "../Crypto/Crypto.hpp"

// NOTE: all of the "raw data" types (bytes, bytes32) are assumed to already be in hex string format!

// NOTE: the below is incomplete and handles sum types in a dumb way but works for my purposes
// maybe just make everything in hex?

namespace Abi {

bool is_dynamic(std::string type) {
    if (type == "bytes" || type == "string")
        return true;
    else if (type[type.size()-2] == '[' && type[type.size() - 1] == ']')
        return true;
    else if (type[type.size() - 1] == ']') {
        int t = 0;
        for (int i = 0; i < type.size(); i++) {
            if (type[i] == '[') {
                t = i;
            }
        }
        assert(t != 0);
        return is_dynamic(type.substr(0, t));
    }
    else
        return false;
}

bool is_static(std::string type) {
    return !is_dynamic(type);
}
namespace Encode {
    std::string padleft(std::string in) {
        return std::string(64 - in.size(), '0') + in;
    }

    std::string padright(std::string in) {
        return in + std::string(64 - in.size(), '0');
    }

    std::string encode_uint(unsigned int i) {
        std::stringstream ss;
        ss << std::hex << i;
        return padleft(ss.str());
    }

    std::string encode_address(std::string addr) {
        assert(addr.size() == 40);
        return padleft(addr);
    }

    std::string encode_bytes32_arr(std::vector<std::string> in) {
        std::string out = "";
        out += encode_uint(in.size());
        for (std::string e : in) {
            out += padleft(e);
        }
        return out;
    }

    std::string encode_bytes(std::string in) {
        std::string out = "";
        out += encode_uint(in.size() / 2);

        int zeroes_needed = 64 - (in.size() % 64);
        if (zeroes_needed == 64)
            zeroes_needed = 0;
        out += in + std::string(zeroes_needed, '0');
        return out;
    }

    std::string encode_bool_arr(std::vector<bool> in) {
        std::string out = "";
        out += encode_uint(in.size());
        for (bool b : in) {
            out += encode_uint((unsigned int) b);
        }
        return out;
    }

    std::string encode_uint_arr(std::vector<unsigned int> in) {
        std::string out = "";
        out += encode_uint(in.size());
        for (unsigned int i : in)
            out += encode_uint(i);
        return out;
    }

    std::string encode_static(std::string type, ValueType value) {
        assert(is_static(type));
        if (type.substr(0, 4) == "uint")
            return encode_uint(value.unsigned_int);
        if (type.substr(0, 3) == "int")
            return "UNIMPLEMENTED";
        if (type == "bool")
            return encode_uint((unsigned int)value.boolean);
        if (type.substr(0, 5) == "bytes")
            return padright(value.str);
        if (type == "address") {
            std::string addr = value.str;
            if (addr[1] == 'x')
                return padleft(addr.substr(2, addr.size()));
            else
                return padleft(addr);
        }

        return "UNIMPLEMENTED";
    }

    std::string encode_dynamic(std::string type, ValueType value) {
        assert(is_dynamic(type));
        if (type == "bytes")
            return encode_bytes(value.str);
        if (type == "bool[]") {
            std::vector<bool> in;
            for (bool v : value.boolarr)
                in.push_back(v);
            return encode_bool_arr(in);
        }
        if (type == "bytes32[]") {
            std::vector<std::string> in;
            for (std::string v : value.bytearr)
                in.push_back(v);
            return encode_bytes32_arr(in);
        }
        if (type == "uint32[]") {
            std::vector<unsigned int> in;
            for (unsigned int v : value.uintarr)
                in.push_back(v);
            return encode_uint_arr(in);
        }
        return "UNIMPLEMENTED";
    }

    std::string encode_call(std::string fun_sig, std::vector<std::string> types, std::vector<ValueType> values) {
        std::string out = "";

        out += Crypto::ToHex(Crypto::SHA3(fun_sig.data(), fun_sig.size())).substr(0, 8); //first four bytes of function signature hash

        assert(types.size() == values.size());
        int num_params = types.size();

        std::vector<std::string> encodings;

        // do all encodings
        for (int i = 0; i < num_params; i++) {
            if (is_static(types[i]))
                encodings.push_back(encode_static(types[i], values[i]));
            else
                encodings.push_back(encode_dynamic(types[i], values[i]));
        }

        size_t size_of_head = 32 * encodings.size(); //size of static data & indices for dynamic
        size_t ctr = size_of_head; //ctr is for offsets


        for (int i = 0; i < num_params; i++) { // head part
            if (is_static(types[i])) {
                out += encodings[i];
            }
            else {
                out += encode_uint(ctr);
                ctr += encodings[i].size() / 2;
            }
        }

        for (int i = 0; i < num_params; i++) { // tail part (dynamic data)
            if (is_dynamic(types[i])) {
                out += encodings[i];
            }
        }

        return out;

    }

}

namespace Decode {
    std::string decode_bytes32(std::string data) {
        return data;
    }
    unsigned int decode_uint(std::string data) {
        return std::stoi(data, nullptr, 16);
    }
    bool decode_bool(std::string data) {
        return (bool)decode_uint(data);
    }
    std::string decode_bytes(std::string data) {
        size_t numbytes = decode_uint(data.substr(0, 64));
        return data.substr(64, (numbytes * 2));
    }
    std::vector<std::string> decode_bytes32arr(std::string data) {
        size_t num = decode_uint(data.substr(0, 64));
        int head = 64;
        std::vector<std::string> out;
        for (int i = 0; i < num; i++) {
            out.push_back(decode_bytes32(data.substr(head, 64)));
            head += 64;
        }
        return out;
    }
    std::vector<unsigned int> decode_uint256arr(std::string data) {
        size_t num = decode_uint(data.substr(0, 64));
        int head = 64;
        std::vector<unsigned int> out;
        for (int i = 0; i < num; i++) {
            out.push_back(decode_uint(data.substr(head, 64)));
            head += 64;
        }
        return out;
    }
    std::string decode_address(std::string data) {
        return data.substr(24, 64);
    }

    std::vector<bool> decode_boolarr(std::string data) {
        size_t num = decode_uint(data.substr(0, 64));
        int head = 64;
        std::vector<bool> out;
        for (int i = 0; i < num; i++) {
            out.push_back(decode_bool(data.substr(head, 64)));
            head += 64;
        }
        return out;
    }

    ValueType decode_static(std::string type, std::string data) {
        assert(is_static(type));
        ValueType out;
        if (type == "bool")
            out.boolean = decode_bool(data);
        else if (type == "uint256")
            out.unsigned_int = decode_uint(data);
        else if (type == "bytes32")
            out.str = decode_bytes32(data);
        else if (type == "address")
            out.str = decode_address(data);
        else
            throw std::runtime_error("UNIMPLEMENTED");
        return out;
    }

    ValueType decode_dynamic(std::string type, std::string data) {
        assert(is_dynamic(type));
        ValueType out;
        if (type == "bytes")
            out.str = decode_bytes(data);
        else if (type == "bytes32[]")
            out.bytearr = decode_bytes32arr(data);
        else if (type == "bool[]")
            out.boolarr = decode_boolarr(data);
        else if (type == "uint256[]")
            out.uintarr = decode_uint256arr(data);
        else
            throw std::runtime_error("UNIMPLEMENTED");
        return out;
    }
    std::vector<ValueType> decode_data(std::vector<std::string> types, std::string to_decode) {
        std::string data;
        if (to_decode[1] == 'x')
            data=to_decode.substr(2, to_decode.size());
        else
            data = to_decode;
        std::vector<ValueType> out;
        for (int i = 0; i < types.size(); i++) {
            if (is_static(types[i])) {
                out.push_back(decode_static(types[i], data.substr(64*i, 64)));
            }
            else {
                size_t index = decode_uint(data.substr(64*i, 64)); //index is number of bytes
                out.push_back(decode_dynamic(types[i], data.substr(index*2, data.size())));
            }
        }
        return out;
    }
}
}

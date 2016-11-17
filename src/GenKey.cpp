#include <iostream>
#include "Crypto/Crypto.hpp"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout<<"Usage: "<<argv[0]<<" NAME to make NAME.pk, NAME.sk" << std::endl;
        return -1;
    }
    Crypto::ECCSig::ECDSA_PrivKey sk = Crypto::ECCSig::GenFreshPrivKey();
    Crypto::ECCSig::ECDSA_PubKey pk = Crypto::ECCSig::PrivToPubKey(sk);
    std::string stub (argv[1]);
    Crypto::ECCSig::WritePrivKeyToFile(sk, stub+".sk");
    Crypto::ECCSig::WritePubKeyToFile(pk, stub+".pk");
}

#include "CVerifier/CVerifier.hpp"

int main() {
  Path::Verifiable::Verifier v("../data/client.pk", "../data/server.pk", "../data/params");
  v.MainLoop();
}

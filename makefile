CXX=g++
CPPFLAGS=	-w -Wall -std=c++11 -Wno-reorder -Wno-unknown-pragmas -Wno-sign-compare -g
LDFLAGS= -lboost_filesystem -lboost_system -lboost_iostreams -pthread -lcryptopp -ldevcore -ljsoncpp -ljsonrpccpp-common -ljsonrpccpp-client

UTIL_SRCS= $(wildcard src/util/*.cpp)
UTIL_OBJS = $(UTIL_SRCS:.cpp=.o)

CRYPTO_SRC = src/Crypto/Crypto.cpp
CRYPTO_OBJ = $(CRYPTO_SRC:.cpp=.o)

ABI_SRC = src/abi/abi.cpp
ABI_OBJ = $(ABI_SRC:.cpp=.o)

CLIENT_COMMON_SRC = src/Clients/ListStash.cpp
CLIENT_COMMON_OBJ = $(CLIENT_COMMON_SRC:.cpp=.o)

CLIENT_REQS = $(ABI_OBJ) $(CRYPTO_OBJ) $(UTIL_OBJS) $(CLIENT_COMMON_OBJ)

SERVER_REQS = $(ABI_OBJ) $(CRYPTO_OBJ) $(UTIL_OBJS)

malpathtestclient: src/MaliciousPathOneAccess.o src/Clients/MaliciousPathClient.o $(CLIENT_REQS)
	$(CXX) -o bin/$@ $^ $(CPPFLAGS) $(LDFLAGS)

malpathbinarysearch: src/MaliciousPathBinarySearch.o src/Clients/MaliciousPathClient.o $(CLIENT_REQS)
	$(CXX) -o bin/$@ $^ $(CPPFLAGS) $(LDFLAGS)

malpathserver: src/MaliciousPathServerRunner.o src/Servers/MaliciousPathServer.o src/Servers/MaliciousPathNetworkServer.o $(SERVER_REQS)
	$(CXX) -o bin/$@ $^ $(CPPFLAGS) $(LDFLAGS)

verifpathserver: src/VerifiablePathServerRunner.o src/Servers/VerifiablePathServer.o src/Servers/VerifiablePathNetworkServer.o $(SERVER_REQS)
	$(CXX) -o bin/$@ $^ $(CPPFLAGS) $(LDFLAGS)

verifpathbinarysearch: src/VerifiablePathBinarySearch.o src/Clients/VerifiablePathClient.o $(CLIENT_REQS)
	$(CXX) -o bin/$@ $^ $(CPPFLAGS) $(LDFLAGS)

verifpathtestclient: src/VerifiablePathOneAccess.o src/Clients/VerifiablePathClient.o $(CLIENT_REQS)
	$(CXX) -o bin/$@ $^ $(CPPFLAGS) $(LDFLAGS)

cverifier: src/CVerifierRunner.o src/CVerifier/CVerifier.o $(CRYPTO_OBJ) $(UTIL_OBJS) $(ABI_OBJ)
	$(CXX) -o bin/$@ $^ $(CPPFLAGS) $(LDFLAGS)

malpath: malpathbinarysearch malpathserver malpathtestclient

verifpath: verifpathbinarysearch verifpathserver verifpathtestclient 

################# utility ###################

reset_contract: src/reset_contract.o $(ABI_OBJ) $(CRYPTO_OBJ)
	$(CXX) -o bin/$@ $^ $(CPPFLAGS) $(LDFLAGS)


genkey: $(CRYPTO_OBJ)
	$(CXX) src/GenKey.cpp -o bin/genkey $^ $(CPPFLAGS) $(LDFLAGS)

sim: $(CRYPTO_OBJ) $(ABI_OBJ)
	$(CXX) src/sim_acc/sim.cpp -o bin/sim $^ $(CPPFLAGS) $(LDFLAGS)



.PHONY: clean
clean:
	find src -name '*.o' -delete

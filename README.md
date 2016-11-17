Implementation of Externally Verifiable Path ORAM
=====

Requirements
--
boost, cryptopp, libjson-rpc-cpp, libethereum

Building
--

Type `make malpath` in the main directory to build the malicious-secure ORAM implementation. To build the verifiable implementation, type `make verifpath`. Each will build three executables: the server application, a test client which runs dummy accesses, and a client running binary search over the ORAM instance. To build the implementation of the verifier in C, `make cverifier`.

`make reset_contract` will build the utility used to reset the contract from the administrator account (currently hardcoded into the source).

`make genkey` will build `genkey`, which  generates a fresh elliptic curve keypair, from which you can import into `parity` or `geth`. 

`make sim` will build `sim`, which runs simulated dummy accesses with the ethereum verifier.

Running
--

In the `data` folder, `client.pk`, `client.sk`, `server.pk`, `server.sk` contain the client and server keypairs respectively used by the ethereum-based implementation. `params` is used by the verifiable implementation, and contains three values: 

* a boolean `0/1`: `0` means the verified access is using the ethereum verifier, and `1` means the verified access is using the ethereum verifier;
* an integer, indicating the height of the ORAM tree, and
* an integer, indicating the number of blocks per bucket in the ORAM tree.


Currently, these file locations are hardcoded into the source. Thus, your working directory must be `bin`.

In order to run the ethereum implementation, a local ethereum node must be running which supports Ethereum's JSON RPC. The address of the contract must be placed in `contract.addr`, inside of the `data` directory.

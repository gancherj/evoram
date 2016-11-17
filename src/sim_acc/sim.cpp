#include "../Crypto/Crypto.hpp"
#include <iostream>
#include "../RPCWrapper/RPCWrapper.hpp"
#include <string>
#include <fstream>
struct Params {
	int tree_depth;
	int blocks_per_bucket;
	int bytes_per_block;
};

static inline std::string &rtrim(std::string &s) {
	s.erase(std::find_if(s.rbegin(), s.rend(),
				std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
	return s;
}
inline std::vector<std::string> SplitHexToBytes32(std::string &in) {
	std::vector<std::string> out;
	assert(in.size() % 64 == 0);
	for (int i = 0; i < in.size(); i += 64) {
		out.push_back(in.substr(i, 64));
	}
	return out;
}

std::string HashBucket(std::string bucketdata, std::string lefthash, std::string righthash) {
	// in solidity, sha3(cur_bucket, cur_lower_left, cur_lower_right);
	std::string bucketdatahex = Crypto::ToHex(bucketdata);
	std::string lefthashhex = Crypto::ToHex(lefthash);
	std::string righthashhex = Crypto::ToHex(righthash);
	int zeroes_needed = 64 - (bucketdatahex.size() % 64);
	if (zeroes_needed == 64)
		zeroes_needed = 0;
	std::string hextohash = bucketdatahex + std::string(zeroes_needed, '0') + lefthashhex + righthashhex;
	std::vector<byte> d = Crypto::FromHex(hextohash);
	return Crypto::SHA3((char*)d.data(), d.size());
}

std::string GetRootLeaf0(Params params) {
	std::string zerobucket(params.bytes_per_block * params.blocks_per_bucket, '\0');
	std::string righthash(32, '\0');
	std::string cur_hash(32, '\0');
	for (int i = 0; i < params.tree_depth; i++) {
		cur_hash = HashBucket(zerobucket, cur_hash, righthash);
	}
	return cur_hash;
}

Crypto::ECCSig::ECDSA_HexSignature SignRootAndCount(Crypto::ECCSig::ECDSA_PrivKey sk, std::string root, int count) {
	std::string roothex = Crypto::ToHex(root);
	std::string counthex = Abi::Encode::encode_uint(count);
	std::string msghex = roothex + counthex;
	std::vector<byte> msgvect = Crypto::FromHex(msghex);
	std::string msg((char*)msgvect.data(), msgvect.size());
	std::string sha = Crypto::SHA3(msg);
	return Crypto::ECCSig::Sign(sk, sha);
}

void SimPath(std::string &path, std::string &proof, std::string &root, Params params) {
	int proof_size = params.tree_depth * 32; //32 = hash size
	int path_size = params.tree_depth * params.blocks_per_bucket * params.bytes_per_block;
	proof.resize(proof_size);
	std::fill(proof.begin(), proof.end(), '\0');
	path.resize(path_size);
	std::fill(path.begin(), path.end(), '\0');
	root = GetRootLeaf0(params);
}

int main() {
	int count = 0;
	Params params;
	std::cin>>params.tree_depth;
	std::cin>>params.blocks_per_bucket;
	std::cin>>params.bytes_per_block;

	std::cout<<"Running with depth " << params.tree_depth<<", blocks per bucket "<<params.blocks_per_bucket<<", block size "<<params.bytes_per_block<<std::endl;

	std::string path, proof, root;
	SimPath(path,proof,root, params);
	std::string client_sk_filename = "../data/client.sk";
	std::string server_sk_filename = "../data/server.sk";
	std::string contract_addr_filename = "../data/contract.addr";
	std::string rpcaddr = "http://localhost:8545";

	std::unique_ptr<RPC::RPCWrapper> RPC;
	RPC.reset(new RPC::RPCWrapper(rpcaddr));

	Crypto::ECCSig::ECDSA_PrivKey client_sk = Crypto::ECCSig::LoadPrivKeyFromFile(client_sk_filename);
	Crypto::ECCSig::ECDSA_PubKey client_pk = Crypto::ECCSig::PrivToPubKey(client_sk);
	std::string client_addr = "0x" + Crypto::ECCSig::pk_to_addr(client_pk);


	Crypto::ECCSig::ECDSA_PrivKey  server_sk = Crypto::ECCSig::LoadPrivKeyFromFile(server_sk_filename);
	Crypto::ECCSig::ECDSA_PubKey server_pk = Crypto::ECCSig::PrivToPubKey(server_sk);
	std::string server_addr = "0x" + Crypto::ECCSig::pk_to_addr(server_pk);

	std::ifstream ifs(contract_addr_filename);
	std::string contract_addr( (std::istreambuf_iterator<char>(ifs) ),
			(std::istreambuf_iterator<char>()    ) );
	ifs.close();


	contract_addr = rtrim(contract_addr);

	Crypto::ECCSig::ECDSA_HexSignature client_sig = SignRootAndCount(client_sk, root, count);
	Crypto::ECCSig::ECDSA_HexSignature server_sig = SignRootAndCount(server_sk, root, count);

	RPC->WatchContract(contract_addr);
	RPC->StartRecording();

	RPC->Call(client_addr, contract_addr, "ClientRegister(address,uint256,uint256,uint256,uint256)", {"address", "uint256", "uint256", "uint256", "uint256"},
			{Abi::ValueType::String(server_addr), Abi::ValueType::Uint(params.tree_depth), Abi::ValueType::Uint(params.blocks_per_bucket), Abi::ValueType::Uint(params.bytes_per_block / 32),
			Abi::ValueType::Uint(120)}, 1); //120 = 2 minutes timeout
	// Server handshake
	RPC->WaitForEventsRepost({"Server_handshake_request(address)"});
	RPC->Call(server_addr, contract_addr, "server_handshake()", {}, {}, 2);
	// Client root
	std::cout<<"Submitting client root.."<<std::endl;
	RPC->Call(client_addr, contract_addr, "client_submit_root(bytes32,uint256,bytes32,bytes32)",{"bytes32", "uint256", "bytes32", "bytes32"},
			{Abi::ValueType::String(Crypto::ToHex(root)), // root_c
			Abi::ValueType::Uint(count), //count_c
			Abi::ValueType::String(server_sig.r), // sigma_S (r)
			Abi::ValueType::String(server_sig.s)}, 1); // sigma_S (s)

	RPC::Event e = RPC->WaitForEventsRepost({"Server_verify_request(uint256)", "Cheat_client(string)", "Cheat_server(string)"});
	if (e.event_name != "Server_verify_request(uint256)")
		throw std::runtime_error("cheat!" + e.event_name);
	std::cout<<"found event"<<std::endl;


	std::cout<<"Submitting server root.."<<std::endl;
	// call function server_submit_root(bytes32 root_s, uint256 count_s, bytes32 R_c, bytes32 S_c)
	RPC->Call(server_addr, contract_addr, "server_submit_root(bytes32,uint256,bytes32,bytes32)", {"bytes32","uint256","bytes32","bytes32"}, {
			Abi::ValueType::String(Crypto::ToHex(root)),
			Abi::ValueType::Uint(count),
			Abi::ValueType::String(client_sig.r),
			Abi::ValueType::String(client_sig.s)
			}, 2);

	e = RPC->WaitForEventsRepost({"Client_leaf_request()", "Cheat_client(string)", "Cheat_server(string)"});
	if (e.event_name != "Client_leaf_request()") { //someone cheated!
		std::cout<<"Cheat! "<<e.event_name<<std::endl;
		throw std::runtime_error("cheat");
	}


	// call client_submit_leaf(uint256) using mPreviousBlockPosition
	std::cout<<"Submitting request.."<<std::endl;
	RPC->Call(client_addr, contract_addr, "client_submit_leaf(uint256)", {"uint256"},
			{Abi::ValueType::Uint(0)}, 1);

	e = RPC->WaitForEventsRepost({"Server_path_request(uint256)", "Cheat_client(string)", "Cheat_server(string)"});
	if (e.event_name != "Server_path_request(uint256)")
		throw std::runtime_error("cheat!" + e.event_name);

	std::string hexpathdata = Crypto::ToHex(path);
	std::vector<std::string> hashes;
	hashes.push_back(std::string(64,'0'));
	for (int i = 1; i < params.tree_depth; i++) {
		hashes.push_back(Crypto::ToHex(std::string(32, '\0')));
	}

	Abi::ValueType a; a.bytearr = SplitHexToBytes32(hexpathdata);
	Abi::ValueType p; p.bytearr = hashes;

	std::cout<<"Sending path.."<<std::endl;
	RPC->Call(server_addr, contract_addr, "server_submit_path(bytes32[],bytes32[])", {"bytes32[]", "bytes32[]"}, {
			a,
			p
			}, 2);

	e = RPC->WaitForEventsRepost({"Client_new_path_request(bytes32[],bytes32[])","Cheat_client(string)","Cheat_server(string)"});
	if (e.event_name != "Client_new_path_request(bytes32[],bytes32[])") { //someone cheated!
		std::cout<<"Cheat! "<<e.event_name<<std::endl;
		throw std::runtime_error("cheat");
	}

	Abi::ValueType ap;
	ap.bytearr = SplitHexToBytes32(hexpathdata);
	client_sig = SignRootAndCount(client_sk, root, count + 1);

	RPC->Call(client_addr, contract_addr, "client_submit_new_path(bytes32[],bytes32,uint256,bytes32,bytes32)", {"bytes32[]","bytes32","uint256","bytes32","bytes32"},
			{a,
			Abi::ValueType::String(Crypto::ToHex(root)),
			Abi::ValueType::Uint(count + 1),
			Abi::ValueType::String(client_sig.r),
			Abi::ValueType::String(client_sig.s)}, 1);

	std::cout<<"Reading in path.."<<std::endl;
	e = RPC->WaitForEventsRepost({"Server_new_path_forward(bytes32[],bytes32,uint256,bytes32,bytes32)", "Cheat_client(string)", "Cheat_server(string)"});
	if (e.event_name != "Server_new_path_forward(bytes32[],bytes32,uint256,bytes32,bytes32)")
		throw std::runtime_error("cheat!" + e.event_name);

	server_sig = SignRootAndCount(server_sk, root, count + 1);

	RPC->Call(server_addr, contract_addr, "server_submit_new_root(bytes32,uint256,bytes32,bytes32)", {"bytes32","uint256","bytes32","bytes32"}, {
			Abi::ValueType::String(Crypto::ToHex(root)),
			Abi::ValueType::Uint(count + 1),
			Abi::ValueType::String(server_sig.r),
			Abi::ValueType::String(server_sig.s)
			}, 2);


	e = RPC->WaitForEventsRepost({"Success(bytes32,bytes32)", "Cheat_client(string)", "Cheat_server(string)"});
	if (e.event_name != "Success(bytes32,bytes32)") {
		std::cout<<"Cheat! " << e.event_name << std::endl;
		throw std::runtime_error("cheat");
	}
	std::cout<<"Verified Access Complete"<<std::endl;
	int client_gas = RPC->SumUpGasInLog(1);
	int server_gas = RPC->SumUpGasInLog(2);
 	std::ofstream gaslog("../measure/sim_measure", std::ios::app);
       gaslog << params.tree_depth <<", " << params.blocks_per_bucket << ", " << params.bytes_per_block << ", " << client_gas + server_gas << ", " << client_gas << ", "<<server_gas << std::endl;
	       gaslog.close();
}

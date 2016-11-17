#ifndef RPC_WRAPPER_H
#define RPC_WRAPPER_H

#include "ethclient.h"
#include "../abi/abi.hpp"
#include <memory>
#include <string>
#include <iostream>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include "../Crypto/Crypto.hpp"
#include <chrono>
typedef std::chrono::high_resolution_clock Clock;

namespace RPC {

	struct Event {
		std::string event_name;
		std::string data;
	};

	class RPCWrapper {
		public:
			void StartRecording() {
				recording = true;
				tx_log_1.clear();
				tx_log_2.clear();
			}

			std::string Call(std::string from, std::string to, std::string fun_sig, std::vector<std::string> datatypes, std::vector<Abi::ValueType> values, int record) {
				// returns transaction hash
				try {
					std::string data = "0x"+Abi::Encode::encode_call(fun_sig, datatypes, values);
					std::string txhash = ethc->eth_sendTransaction(data, from, to);
					lastdata = data;
					lastfrom = from;
					lastto = to;
					if (record == 1)
						tx_log_1.push_back(txhash);
					else if (record == 2)
						tx_log_2.push_back(txhash);
					return txhash;
				}
				catch (jsonrpc::JsonRpcException e) {
					throw std::runtime_error(e.what());
				}
			}

			size_t GasUsedBlocking(std::string txhash) {
				std::string h = "";
				while (h == "")
					h = ethc->eth_getGasUsedInTransaction(txhash);
				return std::stoi(h.substr(2,h.size()), nullptr, 16);
			}

			size_t SumUpGasInLog(int log) {
				size_t out = 0;
				if (log == 1)
					for (auto tx : tx_log_1)
						out += GasUsedBlocking(tx);
				else if (log == 2)
					for (auto tx : tx_log_2)
						out += GasUsedBlocking(tx);
				return out;
			}


			RPCWrapper (std::string host) {
				try {
					http.reset(new jsonrpc::HttpClient(host));
					ethc.reset(new ethclient(*http));
					filter_id = "";
				}
				catch (jsonrpc::JsonRpcException e) {
					throw std::runtime_error(e.what());
				}
			}

			void WatchContract(std::string from) {
				try {filter_id = ethc->eth_newFilterListenAll(from);}
				catch (jsonrpc::JsonRpcException e) {
					throw std::runtime_error(e.what());
				}
			} //listen for all events

			void SetEventListener(std::string evsig) {
				events_to_watch.push_back(evsig);
			}

			std::vector<Event> PollForWatchedEvents() {
				if (filter_id == "")
					throw std::runtime_error("Filter not initialized");
				Json::Value val = ethc->eth_getFilterChanges(filter_id);
				int siz = val.size();
				std::vector<Event> events;
				if (siz == 0)
					return events;
				for (int i = 0; i < siz; i++) {
					Json::Value event = val[i];
					for (std::string evsig : events_to_watch) {
						if (event["topics"][0].asString() == "0x"+Crypto::ToHex(Crypto::SHA3(evsig))) {
							events.push_back({evsig, event["data"].asString()});
						}
					}
				}
				return events;
			}

			Event WaitForEvents(std::vector<std::string> events) {
				if (filter_id == "")
					throw std::runtime_error("Filter not initialized");
				while (true) {
					Json::Value val = ethc->eth_getFilterChanges(filter_id);
					int siz = val.size();
					if (siz == 0)
						continue;
					for (int i = 0; i < siz; i++) {
						Json::Value event = val[i];
						std::cout<<"Found event: " << event["topics"][0].asString() << std::endl;
						for (std::string evsig : events) {
							if (event["topics"][0].asString() == "0x"+Crypto::ToHex(Crypto::SHA3(evsig))) {
								return {evsig, event["data"].asString()};
							}
						}
					}
				}
			}

			Event WaitForEventsRepost(std::vector<std::string> events) {
				auto t1 = Clock::now();
				if (filter_id == "")
					throw std::runtime_error("Filter not initialized");
				while (true) {
					Json::Value val = ethc->eth_getFilterChanges(filter_id);

					int siz = val.size();
					for (int i = 0; i < siz; i++) {
						Json::Value event = val[i];
						for (std::string evsig : events) {
							std::cout<<"Found event: " << event["topics"][0].asString() << std::endl;
							if (event["topics"][0].asString() == "0x"+Crypto::ToHex(Crypto::SHA3(evsig))) {
								return {evsig, event["data"].asString()};
							}
						}
					}
					auto t2 = Clock::now();
					auto int_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);
					if (int_ms.count() > 40000 && (lastfrom != "" && lastto != "" && lastdata != "")) {
						std::cout<<"Timed out, reposting.."<<std::endl;
						ethc->eth_sendTransaction(lastdata, lastfrom, lastto);
						t1 = Clock::now();
					}
				}
			}
			
			void UninstallFilter() {
				if (filter_id == "")
					throw std::runtime_error("Filter not initiialized");
				try {
					ethc->eth_uninstallFilter(filter_id);
					filter_id = "";
				}
				catch (jsonrpc::JsonRpcException e) {
					throw std::runtime_error(e.what());
				}
			}

		private:
			bool recording = false;
			std::vector<std::string> tx_log_1;
			std::vector<std::string> tx_log_2;
			std::vector<std::string> events_to_watch;
			std::unique_ptr<jsonrpc::HttpClient> http;
			std::unique_ptr<ethclient> ethc;
			std::string filter_id = "";

			std::string lastfrom;
			std::string lastto;
			std::string lastdata;
	};

}

#endif

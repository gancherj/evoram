#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

// TODO: currently, below constants are hardcoded and shared by both Ring and Path
#define CLIENT_VERIF_PORT 9092
#define SERVER_VERIF_PORT 9093
#define CLIENT_SERVER_PORT 9091

static const size_t BLOCKS_PER_BUCKET(2); // unused for verifiable path
static const size_t REAL_BLOCKS_PER_BUCKET(8);
//static const size_t HEIGHT(2); unused
static const size_t BLOCK_DATA_SIZE(64);
static const size_t EVICTION_RATE(4);

static const std::string SERVER_STORAGE_LOCATION("server/server_storage.data");
static const std::string CLIENT_PARAM_STORAGE_LOCATION("client/client_params.bin");
static const std::string STASH_STORAGE_LOCATION("client/stash_file.bin");



#endif

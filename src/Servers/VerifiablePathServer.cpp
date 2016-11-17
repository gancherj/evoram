#include "../util/BinaryStream.hpp"
#include "VerifiablePathServer.hpp"
#include "../common/Defines.hpp"
#include "../common/Constants.hpp"
#include "../util/StorageDevice.hpp"
#include <iostream>
#include <memory>
#include <vector>
#include "../abi/abi.hpp"
namespace Path {
    namespace Verifiable {
    void Server::SetState(std::string paramsfile, Crypto::ECCSig::ECDSA_PrivKey serversk, Crypto::ECCSig::ECDSA_PubKey clientpk, bool* usingcverifier) {


        std::ifstream params(paramsfile);
        params >> mUsingCVerifier >> mHeight >> mBlocksPerBucket;
        params.close();
        *usingcverifier = mUsingCVerifier;
        mHashSize = 32;
        mSigSize = 64;
        mRoot.reset(new char[mHashSize]);
        mPreviousRoot.reset(new char[mHashSize]);

        mNumBuckets = (1 << mHeight) - 1;
        mNumBlocks = mNumBuckets * mBlocksPerBucket;
        mSizeofInternalBucket = mBlocksPerBucket * sizeof(EncryptedBlock) + mHashSize;

        mDevice.reset(new RAMBlockStorageDevice<char>((mNumBuckets + 1) * mSizeofInternalBucket)); // TODO: change to MMFile

        mClientPublicKey = clientpk;
        mServerPrivateKey = serversk;

       std::cout<<"Server initialized with height "<<mHeight<<", blocks per bucket "<<mBlocksPerBucket<<", block size" << sizeof(EncryptedBlock)<<std::endl;
       std::ofstream pp("../measure/server_gas", std::ios::app);
       pp << std::endl <<mHeight<<", "<<mBlocksPerBucket<<", "<<sizeof(EncryptedBlock);
       pp.close();

    }
    size_t Server::GetBucketId(size_t assoc_leaf, size_t level)
    {
       /* level 0             1
        * level 1           2   3
        * level 2          4 5 6 7
        *
        * assumes leaves are labeled 0,1,2,...,num_leaves
        * and assumes levels are labeled 0,1,2,...,height-1 (descending)
        */
       return (1 << (level)) + (assoc_leaf >> ((mHeight - 1) - level));
    }

    size_t Server::GetSiblingId(size_t assoc_leaf, size_t level) {
        size_t bucketid = GetBucketId(assoc_leaf, level);
        return ((bucketid % 2 == 0) ? bucketid + 1 : bucketid - 1);
    }

    size_t Server::GetHashLocation(size_t bucketid) {
        return mSizeofInternalBucket * bucketid + mBlocksPerBucket * sizeof(EncryptedBlock);
    }

    void Server::GetInitialClientSig(BinaryStream& in) {
        bytes64 sigserial;
        in.Read(sigserial.data, mSigSize);
        mClientSig = Crypto::ECCSig::ParseSignature(sigserial);
        assert(VerifyClientSignedRoot(mClientSig, mRoot.get(), mCount));
    }

    std::string Server::HashBucket(std::string bucketdata, std::string lefthash, std::string righthash) {
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

    void Server::ConstructMerkleTree() {
        size_t bottomLevel = mHeight - 1;
        size_t numLeaves = (1 << (mHeight - 1));

        size_t dataSize = mBlocksPerBucket * sizeof(EncryptedBlock);

        size_t hashLocation;
        size_t bucketLocation;
        size_t bucketId;
        size_t level;
        char bucketdata[dataSize];
        char lhash[mHashSize];
        char rhash[mHashSize];

        std::string hash;
        for (int leaf = 0; leaf < numLeaves; leaf++) { //bottom leaves
            bucketId = GetBucketId(leaf, bottomLevel);
            hashLocation = GetHashLocation(bucketId);
            bucketLocation = mSizeofInternalBucket * bucketId;
            mDevice->PRead(bucketLocation, bucketdata, dataSize);
            memset(lhash, 0, mHashSize);
            memset(rhash, 0, mHashSize);
            hash = HashBucket(std::string(bucketdata, dataSize), std::string(lhash, mHashSize), std::string(rhash, mHashSize));
            mDevice->PWrite(hashLocation, hash.data(), mHashSize);
        }

        for (int j = 2; j <= mHeight; j++) {
            level = mHeight - j;
            for (bucketId = (1 << level); bucketId < (1 << (level + 1)); bucketId++)  {// all bucketIds on that level

                bucketLocation = mSizeofInternalBucket * bucketId;
                hashLocation = GetHashLocation(bucketId);
                mDevice->PRead(bucketLocation, bucketdata, dataSize); // blocks
                mDevice->PRead(GetHashLocation(bucketId * 2), lhash, mHashSize); //then left hash
                mDevice->PRead(GetHashLocation(bucketId * 2 + 1), rhash, mHashSize); //then right hash

                hash = HashBucket(std::string(bucketdata, dataSize), std::string(lhash, mHashSize), std::string(rhash, mHashSize));
                mDevice->PWrite(hashLocation, hash.data(), mHashSize);
            }
        }

        std::cout<<"Merkle tree construction complete! New root is " <<Crypto::ToHex(hash)<< std::endl;
        memcpy(mRoot.get(), hash.data(), mHashSize);
    }

    void Server::SendMerkleProof(size_t assoc_leaf, BinaryStream& output_buffer) { // leaf to root
        char hash[mHashSize];
        for (size_t j = 1; j < mHeight; j++) { //does NOT include root
            size_t level = mHeight - j;
            size_t siblingId = GetSiblingId(assoc_leaf, level);
            size_t siblingHashLocation = GetHashLocation(siblingId);
            mDevice->PRead(siblingHashLocation, hash, mHashSize);
            output_buffer.Write(hash, mHashSize);
        }
    }

    bool Server::VerifyClientSignedRoot(Crypto::ECCSig::ECDSA_HexSignature sig, char* hash, size_t count) {
        std::string roothex = Crypto::ToHex(hash, mHashSize);
        std::string counthex = Abi::Encode::encode_uint(count);
        std::string msghex = roothex + counthex;
        std::vector<byte> msgvect = Crypto::FromHex(msghex);
        std::string msg((char*)msgvect.data(), msgvect.size());
        std::string sha = Crypto::SHA3(msg);
        return Crypto::ECCSig::Verify(mClientPublicKey, sha, sig);
    }

    Crypto::ECCSig::ECDSA_HexSignature Server::SignRootAndCount() {
        std::string roothex = Crypto::ToHex(mRoot.get(), mHashSize);
        std::string counthex = Abi::Encode::encode_uint(mCount);
        std::string msghex = roothex + counthex;
        std::vector<byte> msgvect = Crypto::FromHex(msghex);
        std::string msg((char*)msgvect.data(), msgvect.size());
        std::string sha = Crypto::SHA3(msg);
        return Crypto::ECCSig::Sign(mServerPrivateKey, sha);
    }

    void Server::SendInitialMerkleRoot(BinaryStream& output_buffer) {
        char hash[mHashSize];
        mDevice->PRead(GetHashLocation(1), hash, sizeof(hash));
        memcpy(mRoot.get(), hash, sizeof(hash));


        Crypto::ECCSig::ECDSA_HexSignature hs = SignRootAndCount();
        output_buffer.Write(hash, sizeof(hash));
        output_buffer.Write(Crypto::ECCSig::SerializeSignature(hs).data, sizeof(bytes64));
        std::cout<<"Sent signed root: "<<Crypto::ToHex(hash, mHashSize)<<" with count " << mCount << std::endl;
    }

    void Server::SigExchange(BinaryStream& input_buffer, BinaryStream& output_buffer) {
        mCount++;
        bytes64 in_serial;
        assert(input_buffer.size() == mSigSize + sizeof(Command));
        input_buffer.Read(in_serial.data, mSigSize);
        Crypto::ECCSig::ECDSA_HexSignature hsin = Crypto::ECCSig::ParseSignature(in_serial);
        assert(VerifyClientSignedRoot(hsin, mRoot.get(), mCount)); // TODO: "abort"; tell client to proceed to phase 2
        mClientSig = hsin;
        Crypto::ECCSig::ECDSA_HexSignature hs = SignRootAndCount();

        char hss[64];
        memcpy(hss, Crypto::ECCSig::SerializeSignature(hs).data, mSigSize);

        //std::cout<<"Fuck up signature?"<<std::endl;
        bool b = false;
        //std::cin>>b;
        if (b)
            hss[63] = 'h';
        output_buffer.Write(hss, mSigSize);
    }

    void Server::DummyFill(BinaryStream& input_buffer, BinaryStream& output_buffer) {
        mCount = 0;
        EncryptedBlock empty_enc_block; // need to fill slot 0 with empty first
        size_t empty_index = 0;
        for (size_t i = 0; i < mBlocksPerBucket; i++) {
            mDevice->PWrite(empty_index, &empty_enc_block, sizeof(empty_enc_block));
            empty_index += sizeof(empty_enc_block);
        }

        // now add in dummy blocks sent over by client
        for (size_t bucket_id = 1; bucket_id <= mNumBuckets; ++bucket_id) {
            size_t bucketLocation = mSizeofInternalBucket * bucket_id;
            size_t index = bucketLocation;

            for (size_t i = 0; i < mBlocksPerBucket; ++i) {
                EncryptedBlock encrypted_block;
                input_buffer.Read(&encrypted_block, sizeof(encrypted_block));

                mDevice->PWrite(index, &encrypted_block, sizeof(encrypted_block));
                index += sizeof(encrypted_block);
            }
        }

        ConstructMerkleTree();
        SendInitialMerkleRoot(output_buffer);
    }

    void Server::ReadDataPath(size_t assoc_leaf, BinaryStream& output_buffer) {
        for (size_t j = 1; j <= mHeight; j++) {
            size_t level = mHeight - j; //NOTE: readpath is now going leaf to root, so the merkle proof can be sent alongside it
            size_t bucketId = GetBucketId(assoc_leaf, level);
            size_t bucketLocation = mSizeofInternalBucket * bucketId;
            size_t index = bucketLocation;

            EncryptedBlock enc_block;
            size_t enc_block_size = sizeof(enc_block);

            for (size_t i = 0; i < mBlocksPerBucket; ++i) {
                mDevice->PRead(index + (i * enc_block_size), &enc_block, enc_block_size);
                output_buffer.Write(&enc_block, enc_block_size);
            }
        }
    }

    void Server::ReadPath(size_t assoc_leaf, BinaryStream& output_buffer) {
        ReadDataPath(assoc_leaf, output_buffer);

        SendMerkleProof(assoc_leaf, output_buffer);
    }

    void Server::WritePath(size_t assoc_leaf, BinaryStream& input_buffer) {
        for (size_t j = 1; j <= mHeight; ++j) {
            size_t level = mHeight - j;
            size_t bucketId = GetBucketId(assoc_leaf, level);
            size_t bucketLocation = mSizeofInternalBucket * bucketId;
            size_t index = bucketLocation;

            EncryptedBlock enc_block;
            size_t enc_block_size = sizeof(enc_block);

            for (size_t i = 0; i < mBlocksPerBucket; ++i) {
                input_buffer.Read(&enc_block, enc_block_size);
                mDevice->PWrite(index, &enc_block, enc_block_size);
                index += enc_block_size;
            }
        }
        ConstructMerkleTree();
    }

    void Server::SaveState(BinaryStream& input_buffer, BinaryStream& output_buffer)
    {} //TODO
    void Server::LoadState(BinaryStream& input_buffer, BinaryStream& output_buffer)
    {}

    void Server::RememberCurrentState(size_t leaf_to_store) {
        memcpy(mPreviousRoot.get(), mRoot.get(), mHashSize);
        mPreviousCount = mCount;
        mPreviousClientSig = mClientSig;

        mPreviousPath.reset(new BinaryStream);
        ReadDataPath(leaf_to_store, *mPreviousPath);
        mPreviousPath_leaf = leaf_to_store;
    }

    void Server::RevertToPreviousState() {
        memcpy(mRoot.get(), mPreviousRoot.get(), mHashSize);
        mCount = mPreviousCount;
        mClientSig = mPreviousClientSig;

        WritePath(mPreviousPath_leaf, *mPreviousPath);
    }
}
}

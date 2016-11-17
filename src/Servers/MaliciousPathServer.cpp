#include "../util/BinaryStream.hpp"
#include "MaliciousPathServer.hpp"
#include "../common/Defines.hpp"
#include "../common/Constants.hpp"
#include "../util/StorageDevice.hpp"
#include <iostream>
#include <memory>
#include <vector>

namespace Path {
    namespace Malicious {
    void Server::SetState(std::string paramsfile) {
      std::ifstream params(paramsfile);
      bool b;
      params >> b >> mHeight >> mBlocksPerBucket;
      params.close();
        mHashSize = 32;
        mNumBuckets = (1 << mHeight) - 1;
        mNumBlocks = mNumBuckets * mBlocksPerBucket;
        mSizeofBucket = mBlocksPerBucket * sizeof(EncryptedBlock) + mHashSize;

        //mDevice.reset(new MMFileBlockStorageDevice<char>(SERVER_STORAGE_LOCATION, (mNumBuckets + 1) * mSizeofBucket));
        mDevice.reset(new RAMBlockStorageDevice<char>((mNumBuckets + 1) * mSizeofBucket));

       std::cout<<"Server initialized with height "<<mHeight<<", blocks per bucket "<<mBlocksPerBucket<<std::endl;
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
        return mSizeofBucket * bucketid + mBlocksPerBucket * sizeof(EncryptedBlock);
    }

    void Server::ConstructMerkleTree() {
        size_t bottomLevel = mHeight - 1;
        size_t numLeaves = (1 << (mHeight - 1));

        size_t hashInputSize = mBlocksPerBucket * sizeof(EncryptedBlock) + 2 * mHashSize;
        size_t dataSize = mBlocksPerBucket * sizeof(EncryptedBlock);

        size_t hashLocation;
        size_t bucketLocation;
        size_t bucketId;
        size_t level;
        char hashInput[hashInputSize];


        std::string hash;
        for (int leaf = 0; leaf < numLeaves; leaf++) { //bottom leaves
            bucketId = GetBucketId(leaf, bottomLevel);
            hashLocation = GetHashLocation(bucketId);
            bucketLocation = mSizeofBucket * bucketId;
            mDevice->PRead(bucketLocation, hashInput, dataSize);
            memset(hashInput + dataSize, 0, 2 * mHashSize); // set child hashes to zero
            hash = Crypto::SHA3(hashInput, sizeof(hashInput));
            mDevice->PWrite(hashLocation, hash.data(), mHashSize);
        }

        for (int j = 2; j <= mHeight; j++) {
            level = mHeight - j;
            for (bucketId = (1 << level); bucketId < (1 << (level + 1)); bucketId++)  {// all bucketIds on that level

                bucketLocation = mSizeofBucket * bucketId;
                hashLocation = GetHashLocation(bucketId);
                mDevice->PRead(bucketLocation, hashInput, dataSize); // blocks
                mDevice->PRead(GetHashLocation(bucketId * 2), hashInput + dataSize, mHashSize); //then left hash
                mDevice->PRead(GetHashLocation(bucketId * 2 + 1), hashInput + dataSize + mHashSize, mHashSize); //then right hash

                hash = Crypto::SHA3(hashInput, sizeof(hashInput));
                mDevice->PWrite(hashLocation, hash.data(), mHashSize);
            }
        }

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

    void Server::SendMerkleRoot(BinaryStream& output_buffer) {
        char hash[mHashSize];
        mDevice->PRead(GetHashLocation(1), hash, sizeof(hash));
        output_buffer.Write(hash, sizeof(hash));

    }


    void Server::DummyFill(BinaryStream& input_buffer, BinaryStream& output_buffer) {
        EncryptedBlock empty_enc_block; // need to fill slot 0 with empty first
        size_t empty_index = 0;
        for (size_t i = 0; i < mBlocksPerBucket; i++) {
            mDevice->PWrite(empty_index, &empty_enc_block, sizeof(empty_enc_block));
            empty_index += sizeof(empty_enc_block);
        }

        // now add in dummy blocks sent over by client
        for (size_t bucket_id = 1; bucket_id <= mNumBuckets; ++bucket_id) {
            size_t bucketLocation = mSizeofBucket * bucket_id;
            size_t index = bucketLocation;

            for (size_t i = 0; i < mBlocksPerBucket; ++i) {
                EncryptedBlock encrypted_block;
                input_buffer.Read(&encrypted_block, sizeof(encrypted_block));

                mDevice->PWrite(index, &encrypted_block, sizeof(encrypted_block));
                index += sizeof(encrypted_block);
            }
        }

        ConstructMerkleTree();
        SendMerkleRoot(output_buffer);
    }

    void Server::ReadPath(size_t assoc_leaf, BinaryStream& output_buffer) {
        for (size_t j = 1; j <= mHeight; j++) {
            size_t level = mHeight - j; //NOTE: readpath is now going leaf to root, so the merkle proof can be sent alongside it
            size_t bucketId = GetBucketId(assoc_leaf, level);
            size_t bucketLocation = mSizeofBucket * bucketId;
            size_t index = bucketLocation;

            EncryptedBlock enc_block;
            size_t enc_block_size = sizeof(enc_block);

            for (size_t i = 0; i < mBlocksPerBucket; ++i) {
                mDevice->PRead(index + (i * enc_block_size), &enc_block, enc_block_size);
                output_buffer.Write(&enc_block, enc_block_size);
            }
        }

        SendMerkleProof(assoc_leaf, output_buffer);
    }

    void Server::WritePath(size_t assoc_leaf, BinaryStream& input_buffer) {
        for (size_t j = 1; j <= mHeight; ++j) {
            size_t level = mHeight - j;
            size_t bucketId = GetBucketId(assoc_leaf, level);
            size_t bucketLocation = mSizeofBucket * bucketId;
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

}
}

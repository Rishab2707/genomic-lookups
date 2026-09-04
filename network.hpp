/*
 * network.hpp
 * 
 * Provides serialization and deserialization functions to transmit 128-bit blocks 
 * and DPF keys over Boost.Asio TCP sockets.
 */
#pragma once

#include <boost/asio.hpp>
#include <vector>
#include "dpf.hpp"

using boost::asio::ip::tcp;

// Writes a single 128-bit block to the socket
inline void write_block(tcp::socket& socket, const Block128& block) {
    boost::asio::write(socket, boost::asio::buffer(&block.data, sizeof(__m128i)));
}

// Reads a single 128-bit block from the socket
inline void read_block(tcp::socket& socket, Block128& block) {
    boost::asio::read(socket, boost::asio::buffer(&block.data, sizeof(__m128i)));
}

// Serializes a full DPFKey and writes it to the socket
inline void write_key(tcp::socket& socket, const DPFKey& key) {
    uint32_t party_id = key.party_id;
    uint32_t depth = key.cw.size();
    
    // Send metadata (party ID and tree depth)
    boost::asio::write(socket, boost::asio::buffer(&party_id, sizeof(party_id)));
    boost::asio::write(socket, boost::asio::buffer(&depth, sizeof(depth)));
    
    // Send the initial seed
    write_block(socket, key.seed);
    
    // Send the array of 128-bit correction words (CWs)
    for (size_t i = 0; i < depth; ++i) {
        write_block(socket, key.cw[i]);
    }
    
    // Pack the boolean flags (left and right) into a byte array for efficient transport
    std::vector<uint8_t> bools(depth * 2);
    for (size_t i = 0; i < depth; ++i) {
        bools[2 * i] = key.t_cw_L[i];
        bools[2 * i + 1] = key.t_cw_R[i];
    }
    boost::asio::write(socket, boost::asio::buffer(bools.data(), bools.size()));
}

// Reads a serialized DPFKey from the socket
inline void read_key(tcp::socket& socket, DPFKey& key) {
    uint32_t party_id;
    uint32_t depth;
    
    // Read metadata
    boost::asio::read(socket, boost::asio::buffer(&party_id, sizeof(party_id)));
    boost::asio::read(socket, boost::asio::buffer(&depth, sizeof(depth)));
    
    key.party_id = party_id;
    key.cw.resize(depth);
    key.t_cw_L.resize(depth);
    key.t_cw_R.resize(depth);
    
    // Read the initial seed
    read_block(socket, key.seed);
    
    // Read all correction words
    for (size_t i = 0; i < depth; ++i) {
        read_block(socket, key.cw[i]);
    }
    
    // Read and unpack the boolean flags
    std::vector<uint8_t> bools(depth * 2);
    boost::asio::read(socket, boost::asio::buffer(bools.data(), bools.size()));
    for (size_t i = 0; i < depth; ++i) {
        key.t_cw_L[i] = bools[2 * i];
        key.t_cw_R[i] = bools[2 * i + 1];
    }
}

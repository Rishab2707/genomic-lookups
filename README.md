# Oblivious DNA Trie (DUORAM 2-Phase Protocol)

This repository contains a high-performance, 2-party Distributed Point Function (DPF) system implemented in modern C++. It is specifically designed to store and query DNA sequences (A, T, C, G) completely obliviously using an Implicit Complete Trie architecture.

## Architectural Highlights
*   **Leafless DPF (Payload-Free DPF) & 128x Memory Savings:** Implements payload-free DPFs where the terminal correction word is eliminated. The servers evaluate compact boolean flags (`std::vector<bool>`) representing XOR shares of the standard basis vector $e_r$, reducing the offline buffer footprint from 16 bytes per block to just 1 bit per block (**128x memory reduction**).
*   **DUORAM Offline/Online Shifting:** The client pre-computes shared randomness on the servers (offline phase) and executes a circular shift ($\Delta$) to conditionally inject the 128-bit masked update (online phase).
*   **Oblivious Implicit Complete Trie:** Sequences are mapped mathematically to array indices (`4 * parent + char`), eliminating the need for complex pointer-chasing and incremental DPFs.
*   **High-Density Packing:** DNA characters are 1-hot encoded into 4-bit nibbles, allowing 32 characters to be densely packed into every 128-bit block, massively shrinking the required DPF tree depth.
*   **Access Pattern Padding:** Search and Insert operations execute an exact, fixed number of DPF operations regardless of early failures, guaranteeing zero side-channel leaks.
*   **Hardware Accelerated:** The DPF evaluation expands at millions of nodes per second using Intel's `AES-NI` hardware intrinsics (`-maes`).

## Prerequisites
*   A Linux environment (or Windows Subsystem for Linux - WSL)
*   `g++` with C++20 support
*   Boost C++ Libraries (specifically `boost_system` and `boost_thread`)
    *   Ubuntu/WSL: `sudo apt-get install libboost-all-dev`

## Build Instructions
Clone the repository and compile it using the provided Makefile:
```bash
make
```
This produces three executables: `server`, `client`, and `test_leafless`.

### Running Verification Tests
To run the automated mathematical verification of the Leafless DPF and online cyclic shift:
```bash
./test_leafless
```

## Usage

### 1. Start the Servers (Parties 0 and 1)
You must start two server processes, ideally in separate terminal windows. 
Both servers require a **Port** and the **Database Size** (specified as a power-of-2 number of characters). 

For example, to start a database capable of holding $2^{20}$ characters (~1 million):
```bash
# Terminal 1
./server 8080 20

# Terminal 2
./server 8081 20
```

### 2. Connect the Client
Open a third terminal window and connect the client to both servers. You must provide the IPs and Ports of both servers, followed by the identical Database Size parameter:
```bash
./client 127.0.0.1 8080 127.0.0.1 8081 20
```

### 3. Interactive Commands
Once the client connects, you can execute the following commands obliviously:

*   **`insert <sequence>`**
    *   Inserts a DNA string into the oblivious trie.
    *   *Example:* `insert ATCG`
*   **`search <sequence>`**
    *   Checks if a DNA string exists in the trie. Completely padded to hide failure depth.
    *   *Example:* `search ATCG`
*   **`write <index> <char>`**
    *   Low-level command. Writes a single DNA character (`A`, `T`, `C`, `G`) to a specific flat array index using the DUORAM 2-phase protocol.
    *   *Example:* `write 500 C`
*   **`read <index>`**
    *   Low-level command. Reads a single character from the flat array index.
    *   *Example:* `read 500`
*   **`exit`**
    *   Closes the connection safely.

*Note: The client can also process batch files using standard input redirection (e.g., `./client 127.0.0.1 8080 127.0.0.1 8081 20 < test.txt`).*

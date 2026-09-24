# Oblivious DNA Trie (3-Party DUORAM MPC Architecture)

A high-performance, privacy-preserving 3-party Distributed ORAM (DORAM) system implemented in modern C++20. Designed to store and query genomic DNA sequences (`A`, `T`, `C`, `G`) completely obliviously using an **Implicit Complete Trie** with Boyle-Gilboa-Ishai (BGI) Distributed Point Functions (DPF) and pure **XOR-permutations**.

---

## Architecture Overview

The system implements a true **3-Party MPC (Secure Multi-Party Computation)** protocol consisting of four distinct processes:

```text
                        ┌──────────────────────────────┐
                        │   Offline Dealer (3rd Party) │
                        │        (dealer.cpp)          │
                        └──────────────┬───────────────┘
                                       │
                      Offline Sockets  │  Offline Sockets
                      (Role 0x01)      │  (Role 0x01)
                     (dpf_id, r0, k0)  │  (dpf_id, r1, k1)
                                       │
                 ┌─────────────────────┴─────────────────────┐
                 │                                           │
                 ▼                                           ▼
      ┌─────────────────────┐                     ┌─────────────────────┐
      │  Server 0 (Party 0) │ ◄─────────────────► │  Server 1 (Party 1) │
      │    (server.cpp)     │   Inter-Server TCP  │    (server.cpp)     │
      │    Port 8000        │   (Role 0x03 PEER)  │    Port 8001        │
      └──────────▲──────────┘   Exchange c_share  └──────────▲──────────┘
                 │                                           │
                 │                                           │
                 │  Online Socket (Role 0x02)                │  Online Socket (Role 0x02)
                 │  Target Share: t0                         │  Target Share: t1
                 │  Result Share: ans0                       │  Result Share: ans1
                 │                                           │
                 └─────────────────────┬─────────────────────┘
                                       │
                                       │
                        ┌──────────────┴───────────────┐
                        │   Thin Client (UI / Query)   │
                        │         (client.cpp)         │
                        └──────────────────────────────┘
```

### Key Security & Design Properties

* **Thin Client (Zero Cryptographic Overhead)**: The client does not generate DPF keys, evaluate PRGs, or manage local pools. It only generates uniform random XOR shares of target query indices ($t = t_0 \oplus t_1$) and reconstructs plaintext results ($val = val_0 \oplus val_1$).
* **Oblivious Random Indices**: Random dummy indices $r \in [0, N-1]$ are chosen exclusively by the third-party Dealer. The client is completely unaware of $r$.
* **Target Query Privacy**: Neither the Dealer nor the Servers ever learn the client's target index $t$. The servers only receive uniform random XOR shares $t_0, t_1$.
* **Pure XOR-Permutations (No Additive Modulo Shifts)**: Shift shares are computed via XOR: $c_b = t_b \oplus r_b$, and combined into $c = c_0 \oplus c_1 = t \oplus r$. Database access uses XOR permutations (`DB[i ^ c]`), eliminating cyclic shifts modulo $N$.
* **Dedicated Inter-Server Channel (`ROLE_PEER`)**: Server 0 and Server 1 communicate over a full-duplex TCP socket with deterministic ping-pong synchronization to exchange shift shares and shifted database shares during oblivious reads.
* **Persistent Dealer Daemon with Two-Phase Generation**:
  - *Phase 1 (Warmup)*: Rapidly populates 100 DPF keys with 0 ms delay at startup.
  - *Phase 2 (Idle Replenishment)*: Paced generation every 100 ms (10 keys/sec) during idle time, drawing minimal CPU while keeping server queues saturated under TCP backpressure.
* **Compact DNA Encoding**: DNA characters are 1-hot encoded into 4-bit nibbles, packing 32 characters into every 128-bit block (`__m128i`).
* **Hardware Accelerated**: DPF evaluation utilizes Intel `AES-NI` hardware intrinsics (`-maes`) for wire-speed PRG expansion.

---

## Prerequisites

* **Operating System**: Linux (Ubuntu 20.04+, Debian, Fedora, Arch) or Windows Subsystem for Linux (WSL).
* **Compiler**: `g++` (version 10 or later supporting `-std=c++20`).
* **Hardware Features**: x86_64 CPU with `AES-NI` and `SSE4.1` support.
* **Libraries**: Boost C++ Libraries (`boost_system`, `boost_thread`).

### Installing Dependencies

**Ubuntu / Debian / WSL**:
```bash
sudo apt-get update
sudo apt-get install -y build-essential libboost-all-dev
```

**Fedora / RHEL**:
```bash
sudo dnf install -y gcc-c++ make boost-devel
```

---

## Build Instructions

Clone the repository and build all executables using `make`:

```bash
make clean all
```

This compiles three executables:
1. `server`: The computation party daemon (`server.cpp`).
2. `dealer`: The independent offline randomness generator (`dealer.cpp`).
3. `client`: The interactive thin client terminal (`client.cpp`).

---

## Step-by-Step Execution & Verification Guide

To run a complete end-to-end 3-party test, open **four separate terminal windows** (or use `tmux`).

### Step 1: Start Server 0 (Party 0)
In **Terminal 1**, run Server 0 listening on port `8000` with peer Server 1 on port `8001`, database capacity $2^{10} = 1024$ characters (32 blocks):
```bash
./server 0 8000 127.0.0.1 8001 10
```
*Expected Output:*
```text
[Server 0] Listening on port 8000 (Peer: 127.0.0.1:8001) with DB capacity 1024 chars (32 blocks)
```

### Step 2: Start Server 1 (Party 1)
In **Terminal 2**, run Server 1 listening on port `8001` with peer Server 0 on port `8000`:
```bash
./server 1 8001 127.0.0.1 8000 10
```
*Expected Output:*
```text
[Server 1] Listening on port 8001 (Peer: 127.0.0.1:8000) with DB capacity 1024 chars (32 blocks)
[Server 1] Successfully connected to peer Server 0.
```
*(Server 0 in Terminal 1 will report `[Server 0] Peer connection established.`)*

### Step 3: Launch the Offline Dealer Daemon
In **Terminal 3**, start the Dealer to populate the servers' precomputation queues:
```bash
./dealer 127.0.0.1 8000 127.0.0.1 8001 10
```
*Expected Output:*
```text
[Dealer] Connecting to Server 0 (127.0.0.1:8000)...
[Dealer] Connecting to Server 1 (127.0.0.1:8001)...
[Dealer] Successfully connected to both servers via offline channels.
[Dealer] Running as persistent background daemon (warmup=100 items, idle_interval=100ms)...
[Dealer] Streamed DPF item ID=1 (r_shares generated and DPF keys delivered).
[Dealer] Streamed DPF item ID=50 (r_shares generated and DPF keys delivered).
[Dealer] Warmup complete (100 items primed). Transitioning to idle background generation (interval=100ms).
```
The Dealer continuously supplies DPF keys at 100 ms intervals and automatically pauses when server queues are saturated (capacity: 200 items).

### Step 4: Run the Interactive Client
In **Terminal 4**, connect the client to Server 0 and Server 1:
```bash
./client 127.0.0.1 8000 127.0.0.1 8001 10
```
*Expected Output:*
```text
[Client] Connected to Server 0 and Server 1 (Thin Client mode).
[Client] Database capacity: 1024 characters (32 blocks).
[Client] Maximum supported DNA sequence length: 4 characters.
Available commands: write <index> <char>, read <index>, insert <seq> (max length: 4), search <seq>, help, exit
> 
```

---

## Interactive Command Reference

Once the client prompt (`> `) is active, you can test oblivious read, write, trie insertion, and trie search:

### 1. Oblivious Trie Insert
Inserts a DNA sequence into the oblivious 4-ary trie:
```text
> insert ATCG
Inserted sequence ATCG into oblivious trie.
```

### 2. Oblivious Trie Search
Searches for an existing DNA sequence (returns `FOUND`):
```text
> search ATCG
Sequence ATCG FOUND in trie.
```
Searches for a non-existent sequence (returns `NOT FOUND`):
```text
> search ATCC
Sequence ATCC NOT FOUND.
```
*(Notice: Regardless of whether a sequence matches or fails at the first character, the client executes an identical, constant number of oblivious reads to eliminate side-channel timing leaks).*

### 3. Point Read & Write
Write a single character to a flat index:
```text
> write 42 A
Write completed obliviously.
```
Read the character back from the flat index:
```text
> read 42
Read character at index 42: A (binary: 1)
```

### 4. Exit
```text
> exit
```

---

## Automated Batch Verification

You can verify the entire protocol automatically using standard input redirection from [test.txt](file:///c:/IIT/Kanpur/Thesis/my-thesis/test.txt):

```bash
./client 127.0.0.1 8000 127.0.0.1 8001 10 < test.txt
```

Expected automated output:
```text
[Client] Connected to Server 0 and Server 1 (Thin Client mode).
[Client] Database capacity: 1024 characters (32 blocks).
[Client] Maximum supported DNA sequence length: 4 characters.
Available commands: write <index> <char>, read <index>, insert <seq> (max length: 4), search <seq>, help, exit
> Inserted sequence ATCG into oblivious trie.
> Sequence ATCG FOUND in trie.
> Sequence ATCC NOT FOUND.
> 
```

---

## Advanced Dealer Configuration Options

The Dealer supports fine-tuned control over the offline generation rate and buffering:

| Option | Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| **Idle Interval** | `--interval <ms>` / `-i` | `100` | Sleep duration (in ms) between keys during steady state. |
| **Warmup Count** | `--warmup <N>` / `-w` | `100` | Number of keys burst-generated at startup with 0 ms delay. |
| **Total Count** | `--count <N>` / `-c` | `0` (infinite) | Total keys to generate before exiting (useful for benchmarks). |

**Examples:**
```bash
# Faster replenishment (50ms interval, 200-key initial burst):
./dealer 127.0.0.1 8000 127.0.0.1 8001 10 --interval 50 --warmup 200

# Benchmark/finite mode (generates exactly 500 keys and exits cleanly):
./dealer 127.0.0.1 8000 127.0.0.1 8001 10 --count 500
```

---

## File Structure

* [dealer.cpp](file:///c:/IIT/Kanpur/Thesis/my-thesis/dealer.cpp): Standalone offline Dealer daemon that generates random dummy indices $r$, XOR shares $(r_0, r_1)$, and BGI DPF keys $(k_0, k_1)$.
* [server.cpp](file:///c:/IIT/Kanpur/Thesis/my-thesis/server.cpp): Party 0 & Party 1 server with inter-server TCP socket, offline precomputation queue, and online XOR-permutation read/write handlers.
* [client.cpp](file:///c:/IIT/Kanpur/Thesis/my-thesis/client.cpp): Thin terminal UI client implementing target splitting, plaintext reconstruction, and 4-ary trie traversal.
* [pool.hpp](file:///c:/IIT/Kanpur/Thesis/my-thesis/pool.hpp): Thread-safe bounded FIFO queue (`ThreadSafeQueue`) for server precomputation buffering with backpressure.
* [network.hpp](file:///c:/IIT/Kanpur/Thesis/my-thesis/network.hpp): Serialization protocol for 128-bit blocks, DPF keys, and role-based handshake (`ROLE_OFFLINE`, `ROLE_ONLINE`, `ROLE_PEER`).
* [dpf.hpp](file:///c:/IIT/Kanpur/Thesis/my-thesis/dpf.hpp) / [dpf.cpp](file:///c:/IIT/Kanpur/Thesis/my-thesis/dpf.cpp): Boyle-Gilboa-Ishai (BGI) Leafless Distributed Point Function generation and full evaluation.
* [prg.hpp](file:///c:/IIT/Kanpur/Thesis/my-thesis/prg.hpp) / [prg.cpp](file:///c:/IIT/Kanpur/Thesis/my-thesis/prg.cpp): AES-NI hardware-accelerated pseudorandom generator.
* [Makefile](file:///c:/IIT/Kanpur/Thesis/my-thesis/Makefile): Build configuration compiling `server`, `client`, and `dealer`.

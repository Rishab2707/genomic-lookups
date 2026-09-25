# XOR-shared 3-party DUORAM for genomic data

This project stores packed DNA characters in XOR-shared 128-bit database words. Each word contains 32 four-bit characters, with character `i` in nibble `(i % 32) * 4` of block `i / 32`.

The genomic encoding is one-hot:

| Character | Nibble |
|---|---:|
| null | `0000` |
| A | `0001` |
| C | `0010` |
| T | `0100` |
| G | `1000` |

P0 and P1 hold XOR shares of the database and address. P2 is the stateful, non-colluding helper: it supplies Du–Atallah AND-triple shares, keeps the two blind vectors, and helps with the three-party read/update equations. P2 does not receive either target-address share. Its online address input is the XOR of fresh-random-masked shares, which is a uniform permutation offset.

The joint DPFs are leafless. Each key starts from a 128-bit seed; expansion produces 128-bit leaf labels and XOR-shared flag leaves. No terminal correction word is added to a DPF key. During update, parties derive deferred correction words from the leaf labels and the XOR-shared value delta.

Online address correction is the XOR permutation `output[x ^ c] = input[x]`, matching the project's XOR-shared addresses and power-of-two block domain. READ and UPDATE communication is independent of database size; local DPF expansion and vector operations still take work proportional to the number of blocks. INIT transfers the cached peer-blinded database share once.

## Build

```bash
make all
```

The build requires a C++20 compiler, Boost.Asio/Boost.System, and an x86-64 CPU with AES-NI and SSE4.1.

## Run

Start the servers first, then the dealer, then the client. The default P2 helper port is 8002.

```bash
./server 0 8000 127.0.0.1 8001 10
./server 1 8001 127.0.0.1 8000 10
./dealer 127.0.0.1 8000 127.0.0.1 8001 10
./client 127.0.0.1 8000 127.0.0.1 8001 10
```

The final argument is `log2(database character capacity)`. For example, `10` creates 1024 characters, or 32 packed blocks. The dealer accepts `--helper-port <port>`, `--count <N>`, `--warmup <N>`, and `--interval <ms>` options. With a finite `--count`, preprocessing stops at N items but the dealer stays running as the online helper until it receives Ctrl-C.

The client supports point `read`, point `write`, trie `insert`, and `search`. Point writes first read the existing nibble, then XOR-share the 128-bit packed-block delta between P0 and P1.

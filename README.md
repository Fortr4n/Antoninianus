# Antoninianus [ANT]

Tribus Algo PoW/PoS Hybrid Cryptocurrency - Forked from Denarius

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Fortr4n/Antoninianus/blob/master/COPYING)
[![Build Status](https://github.com/Fortr4n/Antoninianus/actions/workflows/ci.yml/badge.svg)](https://github.com/Fortr4n/Antoninianus/actions)

## Introduction

Antoninianus is a privacy-focused, hybrid cryptocurrency forked from Denarius with modernized cryptographic foundations.

**Ticker:** ANT

Antoninianus [ANT] is an optionally anonymous, decentralized, energy efficient, Proof-of-Work (Tribus Algorithm) and Proof-of-Stake cryptocurrency.

## What's New in v4.0.0

- **OpenSSL 3.x Support** - Full migration to modern cryptographic APIs
- **Comprehensive EVP API** - EVP_PKEY, EVP_DigestSign/Verify, EVP_MAC
- **Modernized CI/CD** - GitHub Actions with multi-platform builds
- **Security Hardened** - Removed all deprecated OpenSSL functions

## Supported Operating Systems

- Linux 64-bit (Ubuntu 22.04+ recommended)
- Windows 64-bit
- macOS 11+

## Building from Source

### Linux (Ubuntu 22.04+)

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install build-essential libssl-dev libdb++-dev \
    libboost-all-dev libqt5gui5 libqt5core5a libqt5dbus5 \
    qttools5-dev qttools5-dev-tools libprotobuf-dev \
    protobuf-compiler libqrencode-dev libminiupnpc-dev \
    libcurl4-openssl-dev libevent-dev

# Build Qt wallet
qmake antoninianus-qt.pro
make -j$(nproc)
```

### macOS

```bash
# Install dependencies via Homebrew
brew install openssl@3 boost berkeley-db@4 qt@5 miniupnpc libqrencode

# Build
qmake antoninianus-qt.pro
make -j$(sysctl -n hw.ncpu)
```

## Specifications

| Parameter      | Value          |
| -------------- | -------------- |
| Total Supply   | 10,000,000 ANT |
| Block Time     | 30 seconds     |
| Stake Interest | 6% annual      |
| Confirmations  | 10 blocks      |
| Maturity       | 30 blocks      |
| Min Stake Age  | 8 hours        |
| P2P Port       | 33369          |
| RPC Port       | 32369          |

## Technology

- Hybrid PoW/PoS Fortuna Stakes
- Decentralized Domain Names (NVS)
- Stealth Addresses
- Ring Signatures (16 Recommended)
- Native Optional Tor Onion Node
- Encrypted Messaging
- Multi-Signature Addresses & TXs
- Atomic Swaps (BIP65 CLTV)
- BIP39 Support (Coin Type 116)
- Proof of Data Timestamping
- Tribus PoW Algorithm
- Jupiter IPFS Integration

## Development

Developers work in their own trees, then submit pull requests when ready.

The master branch is regularly built and tested via GitHub Actions CI.

## Credits

Antoninianus is forked from [Denarius](https://github.com/carsenk/denarius) by @carsenk.

## License

Antoninianus is released under the MIT License. See [COPYING](COPYING) for details.

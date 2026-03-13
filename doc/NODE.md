# Bitcoin Full Node Setup Guide

This document provides step-by-step instructions for setting up a Bitcoin full node to fetch unlimited blocks for the PIR project.

---

## Overview

A local Bitcoin node (Bitcoin Core) provides:
- ✅ **Unlimited block access** - No API rate limits
- ✅ **Full block data** - Complete transactions, inputs, outputs, scripts
- ✅ **Raw binary format** - True Bitcoin block serialization
- ✅ **Local RPC access** - Fast, no network latency
- ✅ **Testnet support** - Use testnet for development (no real money)

---

## Prerequisites

### System Requirements

- **Disk Space**: 500+ GB (mainnet full blockchain) or 50 GB (testnet)
- **RAM**: 8 GB+ recommended, 4 GB minimum
- **OS**: macOS, Linux, or Windows
- **Network**: Stable internet connection (for initial sync)

### Time Investment

- **Initial sync**: 2-7 days for mainnet, 1-3 hours for testnet
- **Ongoing**: Minimal maintenance

---

## Option 1: Testnet Setup (RECOMMENDED for Development)

Testnet uses "fake" Bitcoin - perfect for development without real money.

### Step 1: Install Bitcoin Core

#### macOS (Homebrew)
```bash
# Install Bitcoin Core
brew install bitcoin

# Verify installation
bitcoind -version
# Expected: Bitcoin Core version 26.0 or higher
```

#### Ubuntu/Debian (APT)
```bash
# Add Bitcoin PPA
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:bitcoin/bitcoin
sudo apt-get update

# Install Bitcoin Core
sudo apt-get install bitcoind

# Verify installation
bitcoind -version
```

#### From Source (All Platforms)
```bash
# Clone repository
git clone https://github.com/bitcoin/bitcoin.git
cd bitcoin

# Install dependencies
sudo apt-get install \
    build-essential \
    libtool \
    autotools-dev \
    automake \
    pkg-config \
    libssl-dev \
    libevent-dev \
    boost-system-dev \
    libboost-all-dev \
    libboost-system-dev \
    libboost-filesystem-dev \
    libboost-thread-dev \
    libboost-program-options-dev \
    libboost-test-dev

# Compile
./autogen.sh
./configure --disable-tests --disable-bench --without-gui
make -j$(nproc)

# Install
sudo make install
```

### Step 2: Create Configuration

Create Bitcoin configuration directory and config file:

```bash
# Create config directory
mkdir -p ~/.bitcoin

# Create configuration file
cat > ~/.bitcoin/bitcoin.conf << 'EOF'
# Bitcoin Node Configuration for PIR Project

# Network Settings (Testnet)
testnet=1
server=1

# RPC Settings (for Python scripts)
rpcuser=pir
rpcpassword=pir_dev_password_change_this
rpcport=18332
rpcallowip=127.0.0.1

# Data Location
datadir=/Users/cusgadmin/BitcoinPIR/data/bitcoin

# Performance Settings
dbcache=4000
maxmempool=5000
maxconnections=40
EOF

# Secure the config file
chmod 600 ~/.bitcoin/bitcoin.conf
```

### Step 3: Start Bitcoin Node

```bash
# Create data directory
mkdir -p /Users/cusgadmin/BitcoinPIR/data/bitcoin

# Start bitcoind (testnet, daemon mode)
bitcoind -testnet -daemon

# Or run in foreground (for debugging)
# bitcoind -testnet
```

### Step 4: Verify Node is Running

```bash
# Check if bitcoind is running
ps aux | grep bitcoind

# Test RPC connection
curl -s --data-binary \
  '{"jsonrpc":"2.0","id":"curltest","method":"getblockcount","params":[]}' \
  http://pir:pir_dev_password_change_this@127.0.0.1:18332

# Expected response:
# {"result":<blockheight>, "error":null, "id":"curltest"}
```

### Step 5: Monitor Blockchain Sync

```bash
# Check sync progress
curl -s --data-binary \
  '{"jsonrpc":"2.0","id":"curltest","method":"getblockchaininfo","params":[]}' \
  http://pir:pir_dev_password_change_this@127.0.0.1:18332 | \
  python3 -m json.tool | grep -A 2 -B 2 "verificationprogress"

# Progress goes from 0.0 to 1.0
# Typical testnet sync: 1-3 hours
```

---

## Option 2: Mainnet Setup (Production)

Use this for production deployment. **Requires significant disk space and time.**

### Step 1: Install Bitcoin Core

Same as testnet (see Option 1, Step 1)

### Step 2: Create Mainnet Configuration

```bash
cat > ~/.bitcoin/bitcoin.conf << 'EOF'
# Bitcoin Node Configuration for PIR Project (Mainnet)

# Network Settings (Mainnet - testnet=1 is default)
server=1

# RPC Settings
rpcuser=pir
rpcpassword=pir_prod_password_change_this
rpcport=8332
rpcallowip=127.0.0.1

# Data Location
datadir=/Users/cusgadmin/BitcoinPIR/data/bitcoin

# Performance Settings
dbcache=16000
maxmempool=5000
maxconnections=125
prune=10000  # Keep last 10,000 blocks (~50 GB)
EOF

chmod 600 ~/.bitcoin/bitcoin.conf
```

### Step 3: Start Node and Wait for Sync

```bash
# Create data directory
mkdir -p /Users/cusgadmin/BitcoinPIR/data/bitcoin

# Start bitcoind (daemon mode)
bitcoind -daemon

# Monitor progress (this will take DAYS)
tail -f ~/.bitcoin/debug.log
```

### Step 4: Verify Node Sync

```bash
# Check sync status
curl -s --data-binary \
  '{"jsonrpc":"2.0","id":"curltest","method":"getblockchaininfo","params":[]}' \
  http://pir:pir_prod_password_change_this@127.0.0.1:8332 | \
  python3 -m json.tool

# Look for:
# "initialblockdownload": false
# "verificationprogress": 0.99999999
```

---

## Using Bitcoin RPC from Python

### Install Python Bitcoin RPC Library

```bash
# Install requests library
pip install requests

# Or use Python Bitcoin RPC wrapper
pip install python-bitcoinlib
```

### Example: Fetch Blocks via RPC

```python
import requests
import json

RPC_URL = "http://pir:pir_dev_password_change_this@127.0.0.1:18332"

def get_latest_block_hash() -> str:
    """Get the hash of the latest block."""
    payload = {
        "jsonrpc": "2.0",
        "id": "getbestblockhash",
        "method": "getbestblockhash",
        "params": []
    }
    response = requests.post(RPC_URL, json=payload)
    result = response.json()
    return result["result"]


def get_block(block_hash: str) -> dict:
    """Get block data by hash."""
    payload = {
        "jsonrpc": "2.0",
        "id": "getblock",
        "method": "getblock",
        "params": [block_hash, 0]  # 0 = get full block data
    }
    response = requests.post(RPC_URL, json=payload)
    result = response.json()
    return result["result"]


def get_block_by_height(height: int) -> dict:
    """Get block by height."""
    payload = {
        "jsonrpc": "2.0",
        "id": "getblockhash",
        "method": "getblockhash",
        "params": [height]
    }
    response = requests.post(RPC_URL, json=payload)
    block_hash = response.json()["result"]
    
    # Then get full block data
    return get_block(block_hash)


# Example: Fetch latest 100 blocks
print("Fetching 100 blocks from local Bitcoin node...")
latest_hash = get_latest_block_hash()

blocks = []
current_hash = latest_hash
for i in range(100):
    block = get_block(current_hash)
    blocks.append(block)
    current_hash = block.get("prevblock")
    print(f"[{i+1}/100] Height {block['height']}: {len(block.get('tx', []))} txs")

print(f"\n✓ Successfully fetched {len(blocks)} blocks")
```

---

## Data Location

### Testnet
- **Blocks**: `~/Library/Application Support/Bitcoin/testnet3/blocks/`
- **RPC Log**: `~/.bitcoin/testnet3/debug.log`
- **Configuration**: `~/.bitcoin/bitcoin.conf`

### Mainnet
- **Blocks**: `~/Library/Application Support/Bitcoin/blocks/`
- **RPC Log**: `~/.bitcoin/debug.log`
- **Configuration**: `~/.bitcoin/bitcoin.conf`

---

## Common Commands

### Check Node Status
```bash
# Get blockchain info
curl -s --data-binary '{"jsonrpc":"2.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://pir:pir_dev_password_change_this@127.0.0.1:18332 | python3 -m json.tool

# Get connection count
curl -s --data-binary '{"jsonrpc":"2.0","id":"1","method":"getconnectioncount","params":[]}' \
  http://pir:pir_dev_password_change_this@127.0.0.1:18332 | python3 -m json.tool

# Get mempool info
curl -s --data-binary '{"jsonrpc":"2.0","id":"1","method":"getrawmempool","params":[]}' \
  http://pir:pir_dev_password_change_this@127.0.0.1:18332 | python3 -m json.tool
```

### Stop Node
```bash
# Graceful shutdown
bitcoin-cli -testnet stop

# Or kill process
pkill bitcoind
```

### Restart Node
```bash
# Stop first
bitcoin-cli -testnet stop

# Wait for clean shutdown
sleep 5

# Start again
bitcoind -testnet -daemon
```

---

## Troubleshooting

### Node Won't Start
```bash
# Check for existing process
ps aux | grep bitcoind

# Kill existing if needed
pkill bitcoind

# Check debug log
tail -100 ~/.bitcoin/debug.log

# Check for port conflicts
lsof -i :18332  # testnet
lsof -i :8332   # mainnet
```

### RPC Connection Refused
```bash
# Verify bitcoind is running
ps aux | grep bitcoind

# Verify RPC credentials
cat ~/.bitcoin/bitcoin.conf | grep rpc

# Test connection
curl -v http://pir:pir_dev_password_change_this@127.0.0.1:18332
```

### Out of Disk Space
```bash
# Check disk usage
df -h

# If full, consider pruning
# Add to bitcoin.conf: prune=550
# This keeps last 550 MB of blockchain
```

---

## Next Steps After Setup

Once the Bitcoin node is synced and running:

1. **Update fetch_blocks.py** to use RPC instead of API
2. **Fetch 100 blocks** locally (no rate limits!)
3. **Store in binary format** ready for PIR
4. **Proceed to Phase 2**: Implement Single-Server PIR

---

## Alternative: Bitcoin Testnet in Docker

For easier setup and teardown:

```bash
# Run Bitcoin testnet in Docker
docker run -d \
  --name bitcoin-testnet \
  -p 18332:18332 \
  -v /Users/cusgadmin/BitcoinPIR/data/bitcoin:/data \
  -e RPCUSER=pir \
  -e RPCPASSWORD=pir_dev_password \
  ruimarinho/bitcoin-core:latest \
  bitcoind -testnet -server=1 -rpcuser=pir -rpcpassword=pir_dev_password

# Check logs
docker logs -f bitcoin-testnet
```

---

## Security Notes

⚠️ **IMPORTANT**: Change default passwords in configuration files!

- **testnet password**: `pir_dev_password_change_this`
- **mainnet password**: `pir_prod_password_change_this`
- **RPC binds only to localhost**: Safe for development
- **Use separate credentials** for production

---

## References

- **Bitcoin Core**: https://bitcoincore.org/
- **RPC API Docs**: https://developer.bitcoin.org/reference/rpc/
- **Testnet Faucet**: https://coinfaucet.eu/en/btc-testnet
- **Bitcoin Wiki**: https://en.bitcoin.it/wiki/

---

**Time Estimate**: 1-3 hours (testnet) or 2-7 days (mainnet sync)

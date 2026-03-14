#!/bin/bash
# Test script for lookup_script binary
# Tests various script hashes to verify multi-chunk handling

set -e

echo "=== Building lookup_script binary ==="
cargo build --bin lookup_script --release 2>&1 | grep -v "^warning"

echo ""
echo "=== Test 1: First entry in cuckoo index ==="
cargo run --release --bin lookup_script -- 09d9fb5e2c298cdf69a06fdc188334305e9cb20d --hash 2>&1 | grep -v "^warning"

echo ""
echo "=== Test 2: Entry at index 100 ==="
cargo run --release --bin lookup_script -- db9a42e4eb5bba6affeea8bc55713edbcc8df4cd --hash 2>&1 | grep -v "^warning"

echo ""
echo "=== Test 3: Entry at index 500 ==="
cargo run --release --bin lookup_script -- c9c38d208503e6086c3b0dfe28c3b0800cb2e008 --hash 2>&1 | grep -v "^warning"

echo ""
echo "=== Test 4: Entry at index 1000 ==="
cargo run --release --bin lookup_script -- b5e0bd8918c473b25a55a3d206aaf28623965dd1 --hash 2>&1 | grep -v "^warning"

echo ""
echo "=== Test 5: Entry at index 5000 ==="
cargo run --release --bin lookup_script -- 15807410ff4c86958498a1dee55937bdb5982d7b --hash 2>&1 | grep -v "^warning"

echo ""
echo "=== Test 6: Entry at index 10000 ==="
cargo run --release --bin lookup_script -- 88d6f3fb3385b463b93da98cc9c73e0f638e7b14 --hash 2>&1 | grep -v "^warning"

echo ""
echo "=== All tests completed ==="
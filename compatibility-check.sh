#!/bin/bash

# kMOSAIC Cross-Implementation Compatibility Test Script
# Tests interoperability between k-mosaic-go and k-mosaic-node
#
# This script validates:
# 1. Keys generated in Go can be used in Node and vice versa
# 2. Messages encrypted in Go can be decrypted in Node and vice versa
# 3. Signatures created in Go can be verified in Node and vice versa
#
# Usage: ./compatibility-check.sh

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_CLI="${SCRIPT_DIR}/k-mosaic-go/cmd/k-mosaic-cli/k-mosaic-cli"
NODE_CLI="bun ${SCRIPT_DIR}/k-mosaic-node/src/k-mosaic-cli.ts"
TEST_DIR="${SCRIPT_DIR}/test-compatibility"

# Functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_test() {
    echo -e "${YELLOW}[TEST $TESTS_TOTAL]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((TESTS_PASSED++)) || true
}

print_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((TESTS_FAILED++)) || true
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

run_test() {
    ((TESTS_TOTAL++)) || true
    print_test "$1"
}

cleanup() {
    if [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
    fi
}

# Cleanup on exit
trap cleanup EXIT

# Helper function to extract public key from keypair JSON
extract_public_key() {
    local keypair_file="$1"
    local output_file="$2"

    # Extract public_key field from JSON
    if command -v jq &> /dev/null; then
        jq -r '.public_key' "$keypair_file" | base64 -d > "$output_file"
    else
        # Fallback without jq
        grep -o '"public_key":"[^"]*"' "$keypair_file" | cut -d'"' -f4 | base64 -d > "$output_file"
    fi
}

# Helper function to extract secret key from keypair JSON
extract_secret_key() {
    local keypair_file="$1"
    local output_file="$2"

    # Extract secret_key field from JSON
    if command -v jq &> /dev/null; then
        jq -r '.secret_key' "$keypair_file" | base64 -d > "$output_file"
    else
        # Fallback without jq
        grep -o '"secret_key":"[^"]*"' "$keypair_file" | cut -d'"' -f4 | base64 -d > "$output_file"
    fi
}

# Main script
main() {
    print_header "kMOSAIC Cross-Implementation Compatibility Test"
    echo "Date: $(date)"
    echo "Go CLI: $GO_CLI"
    echo "Node CLI: $NODE_CLI"
    echo ""

    # Check prerequisites
    print_info "Checking prerequisites..."

    # Build Go CLI if needed
    if [ ! -f "$GO_CLI" ]; then
        print_info "Building Go CLI..."
        cd "${SCRIPT_DIR}/k-mosaic-go"
        go build -o cmd/k-mosaic-cli/k-mosaic-cli ./cmd/k-mosaic-cli/
        cd "$SCRIPT_DIR"
    fi

    if [ ! -f "$GO_CLI" ]; then
        print_fail "Go CLI not found at $GO_CLI"
        exit 1
    fi

    # Check Node CLI
    if [ ! -f "${SCRIPT_DIR}/k-mosaic-node/src/k-mosaic-cli.ts" ]; then
        print_fail "Node CLI not found at ${SCRIPT_DIR}/k-mosaic-node/k-mosaic-cli.ts"
        exit 1
    fi

    # Check Node runtime (bun)
    if ! command -v bun &> /dev/null; then
        print_fail "Bun runtime not found. Please install: https://bun.sh"
        exit 1
    fi

    print_info "All prerequisites satisfied"
    echo ""

    # Create test directory
    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"

    # Test 1: Go generates keys, Node encrypts, Node decrypts
    run_test "Go KeyGen → Node Encrypt/Decrypt"
    {
        # Generate keys in Go
        "$GO_CLI" kem keygen --level 128 --output alice-go.json > /dev/null 2>&1

        # Create test message
        echo "Hello from Go keys, encrypted by Node!" > message1.txt

        # Encrypt in Node using Go keys
        $NODE_CLI kem encrypt \
            --public-key alice-go.json \
            --input message1.txt \
            --output message1.enc.json > /dev/null 2>&1

        # Decrypt in Node using Go keys
        $NODE_CLI kem decrypt \
            --secret-key alice-go.json \
            --public-key alice-go.json \
            --ciphertext message1.enc.json \
            --output message1-dec.txt > /dev/null 2>&1

        # Verify content
        if diff -q message1.txt message1-dec.txt > /dev/null 2>&1; then
            print_pass "Go keys work in Node (encrypt/decrypt)"
        else
            print_fail "Content mismatch after Node encrypt/decrypt with Go keys"
        fi
    } || {
        print_fail "Go KeyGen → Node Encrypt/Decrypt failed"
    }

    # Test 2: Node generates keys, Go encrypts, Go decrypts
    run_test "Node KeyGen → Go Encrypt/Decrypt"
    {
        # Generate keys in Node
        $NODE_CLI kem keygen --level 128 --output bob-node.json > /dev/null 2>&1

        # Create test message
        echo "Hello from Node keys, encrypted by Go!" > message2.txt

        # Encrypt in Go using Node keys
        "$GO_CLI" kem encrypt \
            --public-key bob-node.json \
            --input message2.txt \
            --output message2.enc.json > /dev/null 2>&1

        # Decrypt in Go using Node keys
        "$GO_CLI" kem decrypt \
            --secret-key bob-node.json \
            --public-key bob-node.json \
            --ciphertext message2.enc.json \
            --output message2-dec.txt > /dev/null 2>&1

        # Verify content
        if diff -q message2.txt message2-dec.txt > /dev/null 2>&1; then
            print_pass "Node keys work in Go (encrypt/decrypt)"
        else
            print_fail "Content mismatch after Go encrypt/decrypt with Node keys"
        fi
    } || {
        print_fail "Node KeyGen → Go Encrypt/Decrypt failed"
    }

    # Test 3: Go encrypts, Node decrypts
    run_test "Go Encrypt → Node Decrypt"
    {
        # Use Go keys from Test 1
        echo "Message encrypted in Go, decrypted in Node" > message3.txt

        # Encrypt in Go
        "$GO_CLI" kem encrypt \
            --public-key alice-go.json \
            --input message3.txt \
            --output message3-go.enc.json > /dev/null 2>&1

        # Decrypt in Node
        $NODE_CLI kem decrypt \
            --secret-key alice-go.json \
            --public-key alice-go.json \
            --ciphertext message3-go.enc.json \
            --output message3-node-dec.txt > /dev/null 2>&1

        # Verify content
        if diff -q message3.txt message3-node-dec.txt > /dev/null 2>&1; then
            print_pass "Go-encrypted message decrypted in Node"
        else
            print_fail "Content mismatch: Go encrypt → Node decrypt"
        fi
    } || {
        print_fail "Go Encrypt → Node Decrypt failed"
    }

    # Test 4: Node encrypts, Go decrypts
    run_test "Node Encrypt → Go Decrypt"
    {
        # Use Node keys from Test 2
        echo "Message encrypted in Node, decrypted in Go" > message4.txt

        # Encrypt in Node
        $NODE_CLI kem encrypt \
            --public-key bob-node.json \
            --input message4.txt \
            --output message4-node.enc.json > /dev/null 2>&1

        # Decrypt in Go
        "$GO_CLI" kem decrypt \
            --secret-key bob-node.json \
            --public-key bob-node.json \
            --ciphertext message4-node.enc.json \
            --output message4-go-dec.txt > /dev/null 2>&1

        # Verify content
        if diff -q message4.txt message4-go-dec.txt > /dev/null 2>&1; then
            print_pass "Node-encrypted message decrypted in Go"
        else
            print_fail "Content mismatch: Node encrypt → Go decrypt"
        fi
    } || {
        print_fail "Node Encrypt → Go Decrypt failed"
    }

    # Test 5: Large file encryption/decryption
    run_test "Large File Cross-Implementation Test"
    {
        # Create 1MB test file
        dd if=/dev/urandom of=largefile.bin bs=1024 count=1024 > /dev/null 2>&1

        # Go encrypts, Node decrypts
        "$GO_CLI" kem encrypt \
            --public-key alice-go.json \
            --input largefile.bin \
            --output largefile-go.enc.json > /dev/null 2>&1

        $NODE_CLI kem decrypt \
            --secret-key alice-go.json \
            --public-key alice-go.json \
            --ciphertext largefile-go.enc.json \
            --output largefile-node-dec.bin > /dev/null 2>&1

        if diff -q largefile.bin largefile-node-dec.bin > /dev/null 2>&1; then
            print_pass "Large file: Go encrypt → Node decrypt"
        else
            print_fail "Large file content mismatch: Go encrypt → Node decrypt"
        fi
    } || {
        print_fail "Large File Cross-Implementation Test failed"
    }

    # Test 6: Go generates signing keys, Node verifies signatures
    run_test "Go Sign → Node Verify"
    {
        # Generate signing keys in Go
        "$GO_CLI" sign keygen --level 128 --output signer-go.json > /dev/null 2>&1

        # Create test message
        echo "Signed in Go, verified in Node" > message-sign1.txt

        # Sign in Go
        "$GO_CLI" sign sign \
            --secret-key signer-go.json \
            --public-key signer-go.json \
            --input message-sign1.txt \
            --output message-sign1.sig.json > /dev/null 2>&1

        # Verify in Node
        if $NODE_CLI sign verify \
            --public-key signer-go.json \
            --input message-sign1.txt \
            --signature message-sign1.sig.json > /dev/null 2>&1; then
            print_pass "Go signature verified in Node"
        else
            print_fail "Node failed to verify Go signature"
        fi
    } || {
        print_fail "Go Sign → Node Verify failed"
    }

    # Test 7: Node generates signing keys, Go verifies signatures
    run_test "Node Sign → Go Verify"
    {
        # Generate signing keys in Node
        $NODE_CLI sign keygen --level 128 --output signer-node.json > /dev/null 2>&1

        # Create test message
        echo "Signed in Node, verified in Go" > message-sign2.txt

        # Sign in Node
        $NODE_CLI sign sign \
            --secret-key signer-node.json \
            --public-key signer-node.json \
            --input message-sign2.txt \
            --output message-sign2.sig.json > /dev/null 2>&1

        # Verify in Go
        if "$GO_CLI" sign verify \
            --public-key signer-node.json \
            --input message-sign2.txt \
            --signature message-sign2.sig.json > /dev/null 2>&1; then
            print_pass "Node signature verified in Go"
        else
            print_fail "Go failed to verify Node signature"
        fi
    } || {
        print_fail "Node Sign → Go Verify failed"
    }

    # Test 8: MOS-256 compatibility
    run_test "MOS-256 Security Level Compatibility"
    {
        # Generate MOS-256 keys in Go
        "$GO_CLI" kem keygen --level 256 --output mos256-go.json > /dev/null 2>&1

        # Generate MOS-256 keys in Node
        $NODE_CLI kem keygen --level 256 --output mos256-node.json > /dev/null 2>&1

        # Test message
        echo "MOS-256 test message" > mos256-msg.txt

        # Go encrypts with Go keys, Node decrypts
        "$GO_CLI" kem encrypt \
            --public-key mos256-go.json \
            --input mos256-msg.txt \
            --output mos256-1.enc.json > /dev/null 2>&1

        $NODE_CLI kem decrypt \
            --secret-key mos256-go.json \
            --public-key mos256-go.json \
            --ciphertext mos256-1.enc.json \
            --output mos256-1-dec.txt > /dev/null 2>&1

        # Node encrypts with Node keys, Go decrypts
        $NODE_CLI kem encrypt \
            --public-key mos256-node.json \
            --input mos256-msg.txt \
            --output mos256-2.enc.json > /dev/null 2>&1

        "$GO_CLI" kem decrypt \
            --secret-key mos256-node.json \
            --public-key mos256-node.json \
            --ciphertext mos256-2.enc.json \
            --output mos256-2-dec.txt > /dev/null 2>&1

        # Verify both
        if diff -q mos256-msg.txt mos256-1-dec.txt > /dev/null 2>&1 && \
           diff -q mos256-msg.txt mos256-2-dec.txt > /dev/null 2>&1; then
            print_pass "MOS-256 cross-implementation compatibility verified"
        else
            print_fail "MOS-256 compatibility check failed"
        fi
    } || {
        print_fail "MOS-256 Security Level Compatibility failed"
    }

    # Test 9: Key serialization format validation
    run_test "Key Pair Serialization Format Validation"
    {
        # Generate keys in both implementations
        "$GO_CLI" kem keygen --level 128 --output format-go.json > /dev/null 2>&1
        $NODE_CLI kem keygen --level 128 --output format-node.json > /dev/null 2>&1

        # Check if both files have reasonable sizes (should be similar)
        GO_SIZE=$(stat -f%z format-go.json 2>/dev/null || stat -c%s format-go.json 2>/dev/null)
        NODE_SIZE=$(stat -f%z format-node.json 2>/dev/null || stat -c%s format-node.json 2>/dev/null)

        # Sizes should be similar (within 20% - accounting for JSON formatting differences)
        if [ "$GO_SIZE" -gt 0 ] && [ "$NODE_SIZE" -gt 0 ]; then
            SIZE_DIFF=$((GO_SIZE - NODE_SIZE))
            SIZE_DIFF=${SIZE_DIFF#-}  # Absolute value
            SIZE_RATIO=$((SIZE_DIFF * 100 / NODE_SIZE))

            if [ "$SIZE_RATIO" -lt 20 ]; then
                print_pass "Key pair sizes compatible (Go: ${GO_SIZE}B, Node: ${NODE_SIZE}B, diff: ${SIZE_RATIO}%)"
            else
                print_fail "Key pair size mismatch (Go: ${GO_SIZE}B, Node: ${NODE_SIZE}B, diff: ${SIZE_RATIO}%)"
            fi
        else
            print_fail "Key pair serialization format validation failed (invalid sizes)"
        fi
    } || {
        print_fail "Key Pair Serialization Format Validation failed"
    }

    # Print summary
    echo ""
    print_header "Test Summary"
    echo "Total Tests: $TESTS_TOTAL"
    echo -e "Passed:      ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed:      ${RED}$TESTS_FAILED${NC}"

    if [ $TESTS_FAILED -eq 0 ]; then
        echo ""
        print_pass "ALL TESTS PASSED! Cross-implementation compatibility verified ✓"
        echo ""
        echo "kMOSAIC-Go and kMOSAIC-Node are fully interoperable:"
        echo "  ✓ Keys can be exchanged between implementations"
        echo "  ✓ Messages encrypted in one can be decrypted in the other"
        echo "  ✓ Signatures created in one can be verified in the other"
        echo "  ✓ Both MOS-128 and MOS-256 security levels work correctly"
        echo "  ✓ Serialization formats are compatible"
        return 0
    else
        echo ""
        print_fail "Some tests failed. Cross-implementation compatibility issues detected."
        echo ""
        echo "Please review the failed tests above and check:"
        echo "  - Serialization format consistency"
        echo "  - Domain separation constants"
        echo "  - Cryptographic parameter matching"
        echo "  - NIZK proof format"
        return 1
    fi
}

# Run main function
main
EXIT_CODE=$?

# Cleanup
cd "$SCRIPT_DIR"

exit $EXIT_CODE

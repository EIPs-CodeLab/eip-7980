![Language](https://img.shields.io/badge/Language-Go-00ADD8)
![License](https://img.shields.io/badge/License-MIT-green)

# EIP-7980: Ed25519 Transaction Signature Verification

Implementation of EIP-7980 which introduces Ed25519 signature support for Ethereum transactions, enabling cross-chain compatibility and reducing verification costs.

## Overview

EIP-7980 extends Ethereum's transaction signature schemes to support Ed25519, a modern elliptic curve signature algorithm widely used in blockchain ecosystems like Solana, Cosmos, and Polkadot. This implementation allows accounts using Ed25519 keys to interact with Ethereum without requiring key conversion, reducing integration complexity and improving interoperability.

This repository provides a reference implementation in Go, following the official EIP-7980 specification and RFC 8032 standards for Ed25519 signature verification.

## Specification

EIP-7980 defines a new algorithmic type based on EIP-7932 with the following parameters:

| Constant | Value | Description |
|----------|-------|-------------|
| `ALG_TYPE` | `0x00` | Algorithm type identifier for Ed25519 |
| `GAS_PENALTY` | `1000` | Additional gas cost for signature verification |
| `MAX_SIZE` | `96` | Total signature data size (64-byte signature + 32-byte public key) |

### Signature Format

The signature information is exactly 96 bytes structured as follows:

- **Bytes 0-63**: Ed25519 signature (64 bytes)
- **Bytes 64-95**: Ed25519 public key (32 bytes)

### Verification Process

1. Validate that signature_info is exactly 96 bytes
2. Extract signature (first 64 bytes) and public key (last 32 bytes)
3. Verify the Ed25519 signature against the payload hash using RFC 8032 Section 5.1.7
4. Derive Ethereum address by computing keccak256(public_key) and taking the last 20 bytes

## Implementation

### Core Function
```go
func Verify(signatureInfo []byte, payloadHash [32]byte) (ExecutionAddress, error)
```

The `Verify` function takes a 96-byte signature info and a 32-byte payload hash, returning a 20-byte Ethereum address if verification succeeds.

### Installation
```bash
git clone https://github.com/EIPs-CodeLab/eip-7980.git
cd eip-7980
go mod download
```

### Building
```bash
go build -o eip7980 main.go
```

### Running
```bash
go run main.go
```

## Usage Examples

### Basic Verification
```go
package main

import (
    "crypto/ed25519"
    "fmt"
)

func main() {
    // Generate Ed25519 keypair
    publicKey, privateKey, _ := ed25519.GenerateKey(nil)
    
    // Create transaction payload hash
    payloadHash := [32]byte{}
    copy(payloadHash[:], []byte("transaction data"))
    
    // Sign the payload
    signature := ed25519.Sign(privateKey, payloadHash[:])
    
    // Construct 96-byte signature info
    signatureInfo := make([]byte, 96)
    copy(signatureInfo[:64], signature)
    copy(signatureInfo[64:], publicKey)
    
    // Verify and derive address
    address, err := Verify(signatureInfo, payloadHash)
    if err != nil {
        fmt.Printf("Verification failed: %v\n", err)
        return
    }
    
    fmt.Printf("Derived Address: %s\n", address.String())
}
```

### Integration Example
```go
// Verify transaction signature at protocol level
func ValidateTransaction(tx *Transaction) error {
    signatureInfo := tx.GetSignatureInfo() // 96 bytes
    payloadHash := tx.ComputePayloadHash() // 32 bytes
    
    address, err := Verify(signatureInfo, payloadHash)
    if err != nil {
        return fmt.Errorf("invalid signature: %w", err)
    }
    
    if address != tx.From {
        return errors.New("address mismatch")
    }
    
    return nil
}
```

## Test Cases

Run the test suite to verify the implementation:
```bash
# Run all tests
go test ./test -v

# Run specific test
go test ./test -run TestValidSignature -v

# Run with coverage
go test ./test -cover
```

### Test Coverage

- **TestValidSignature**: Verifies correct signature verification with valid inputs
- **TestInvalidLength**: Ensures rejection of incorrectly sized signature data
- **TestInvalidSignature**: Confirms detection of tampered or invalid signatures
- **TestConstants**: Validates EIP-7980 constant values

## Benchmarks

Performance benchmarks are included to measure verification speed:
```bash
go test ./test -bench=. -benchmem
```

Expected performance metrics:

- **Signature Verification**: ~47000 ns/op
- **Address Derivation**: ~360.2 ns/op  
- **Ed25519 Signing**: ~21247 ns/op

## Rationale

### Why Ed25519?

Ed25519 offers several advantages over the traditional ECDSA (secp256k1) used in Ethereum:

**Performance**: Ed25519 signature verification is faster than ECDSA, though this implementation includes a gas penalty to account for computational differences at the protocol level.

**Cross-Chain Compatibility**: Many modern blockchains use Ed25519 as their primary signature scheme. Supporting Ed25519 in Ethereum enables seamless cross-chain account abstraction and reduces the need for bridge-specific key management.

**Simplicity**: Ed25519 has a simpler implementation with fewer edge cases compared to ECDSA, reducing the attack surface for cryptographic vulnerabilities.

**Deterministic Signatures**: Unlike ECDSA which requires careful nonce generation, Ed25519 signatures are deterministic, eliminating an entire class of potential vulnerabilities.

### Design Decisions

**96-Byte Format**: The signature info combines the 64-byte signature and 32-byte public key into a single 96-byte structure for efficient transmission and validation.

**Gas Penalty**: A penalty of 1000 gas units is applied to account for the computational cost of Ed25519 verification, ensuring economic alignment with other signature schemes.

**Address Derivation**: Using keccak256 for address derivation maintains consistency with Ethereum's existing address generation scheme, ensuring compatibility with existing infrastructure.

## Security Considerations
> ⚠️ Note: The official EIP-7980 specification currently leaves "Security Considerations" open for discussion. This section provides a preliminary security analysis based on standard Ed25519 usage and Ethereum transaction model assumptions.


### Implementation Requirements

This implementation strictly follows RFC 8032 Section 5.1.7 for raw Ed25519 verification. It does not use Ed25519ctx or Ed25519ph variants, ensuring compatibility with the EIP-7980 specification.

### Validation Requirements

- Signature info must be exactly 96 bytes
- Public key must be a valid Ed25519 public key
- Signature verification must succeed before address derivation
- No domain separation or context strings are used

### Known Limitations

This is a reference implementation for educational and testing purposes. Production use requires:

- Integration with Ethereum client software
- Comprehensive testing against EIP-7980 test vectors
- Security audit of the complete implementation
- Proper error handling in transaction processing pipeline

### Attack Vectors

**Signature Malleability**: Ed25519 signatures are not malleable, providing protection against signature manipulation attacks.

**Replay Protection**: Transaction replay protection must be handled at the protocol level through nonces and chain IDs, not within the signature verification itself.

**Key Validation**: The implementation validates public key format as part of the Ed25519 verification process.

## References

### Official Specifications

- [EIP-7980 Specification](https://eips.ethereum.org/EIPS/eip-7980)
- [EIP-7932: Algorithmic Transaction Types](https://eips.ethereum.org/EIPS/eip-7932)
- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://datatracker.ietf.org/doc/html/rfc8032)

### Related EIPs

- [EIP-2718: Typed Transaction Envelope](https://eips.ethereum.org/EIPS/eip-2718)
- [EIP-155: Simple replay attack protection](https://eips.ethereum.org/EIPS/eip-155)

### Discussion

- [Ethereum Magicians Discussion Thread](https://ethereum-magicians.org/t/eip-7980-adding-ed25519-as-a-signature-scheme-to-test-eip-7932/24663)



## License

This implementation is provided as-is for educational and reference purposes. Please refer to the repository license file for usage terms.

## Contributing

Contributions are welcome.
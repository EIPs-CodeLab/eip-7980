package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// EIP-7980 Constants
const (
	ALG_TYPE    = byte(0x00) // Algorithm type identifier
	GAS_PENALTY = 1000       // Additional gas cost for Ed25519 verification
	MAX_SIZE    = 96         // Total size: 64 bytes signature + 32 bytes public key
)

// SignatureInfo represents the 96-byte signature data structure
type SignatureInfo struct {
	Signature [64]byte // Ed25519 signature (R + S)
	PublicKey [32]byte // Ed25519 public key
}

// ExecutionAddress represents a 20-byte Ethereum address
type ExecutionAddress [20]byte

// Verify implements the EIP-7980 signature verification algorithm
// This function verifies an Ed25519 signature and derives the Ethereum address
//
// Parameters:
//   - signatureInfo: 96 bytes (64-byte signature + 32-byte public key)
//   - payloadHash: 32-byte hash of the transaction payload
//
// Returns:
//   - ExecutionAddress: 20-byte Ethereum address derived from the public key
//   - error: verification error if signature is invalid
func Verify(signatureInfo []byte, payloadHash [32]byte) (ExecutionAddress, error) {
	// Validate signature_info length (MUST be exactly 96 bytes)
	if len(signatureInfo) != MAX_SIZE {
		return ExecutionAddress{}, fmt.Errorf("invalid signature info length: expected %d, got %d", MAX_SIZE, len(signatureInfo))
	}

	// Split signature_info into signature (first 64 bytes) and public key (last 32 bytes)
	signature := signatureInfo[:64]
	publicKey := signatureInfo[64:96]

	// Verify Ed25519 signature according to RFC 8032 Section 5.1.7
	// This MUST be processed as raw Ed25519 (not Ed25519ctx or Ed25519ph)
	if !ed25519.Verify(publicKey, payloadHash[:], signature) {
		return ExecutionAddress{}, errors.New("ed25519 signature verification failed")
	}

	// Derive Ethereum address from public key using Keccak256
	// Take the last 20 bytes of keccak256(public_key)
	address := deriveAddress(publicKey)

	return address, nil
}

// deriveAddress derives an Ethereum address from an Ed25519 public key
// Returns the last 20 bytes of keccak256(publicKey)
func deriveAddress(publicKey []byte) ExecutionAddress {
	// Compute Keccak256 hash of the public key
	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKey)
	fullHash := hash.Sum(nil)

	// Extract last 20 bytes as Ethereum address
	var address ExecutionAddress
	copy(address[:], fullHash[len(fullHash)-20:])

	return address
}

// ParseSignatureInfo converts raw bytes into structured SignatureInfo
func ParseSignatureInfo(data []byte) (*SignatureInfo, error) {
	if len(data) != MAX_SIZE {
		return nil, fmt.Errorf("invalid data length: expected %d, got %d", MAX_SIZE, len(data))
	}

	sigInfo := &SignatureInfo{}
	copy(sigInfo.Signature[:], data[:64])
	copy(sigInfo.PublicKey[:], data[64:96])

	return sigInfo, nil
}

// ToBytes converts SignatureInfo to raw bytes
func (s *SignatureInfo) ToBytes() []byte {
	result := make([]byte, MAX_SIZE)
	copy(result[:64], s.Signature[:])
	copy(result[64:], s.PublicKey[:])
	return result
}

// String returns hex representation of the address
func (addr ExecutionAddress) String() string {
	return fmt.Sprintf("0x%x", addr[:])
}

// Example usage
func main() {
	fmt.Println("EIP-7980: Ed25519 Transaction Signature Verification")
	fmt.Printf("Algorithm Type: 0x%02x\n", ALG_TYPE)
	fmt.Printf("Gas Penalty: %d\n", GAS_PENALTY)
	fmt.Printf("Max Size: %d bytes\n", MAX_SIZE)

	// Example: Create a test signature (in production, this comes from a transaction)
	// Generate Ed25519 keypair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}

	// Create a mock payload hash (32 bytes)
	payloadHash := [32]byte{}
	copy(payloadHash[:], []byte("example transaction payload hash"))

	// Sign the payload
	signature := ed25519.Sign(privateKey, payloadHash[:])

	// Construct signature_info (96 bytes)
	signatureInfo := make([]byte, MAX_SIZE)
	copy(signatureInfo[:64], signature)
	copy(signatureInfo[64:], publicKey)

	// Verify the signature and derive address
	address, err := Verify(signatureInfo, payloadHash)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		return
	}

	fmt.Printf("\n Signature verified successfully!\n")
	fmt.Printf("Derived Ethereum Address: %s\n", address.String())
}

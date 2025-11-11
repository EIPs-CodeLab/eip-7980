package test

import (
	"crypto/ed25519"
	"testing"

	"golang.org/x/crypto/sha3"
)

// EIP-7980 Constants
const (
	ALG_TYPE    = byte(0x00)
	GAS_PENALTY = 1000
	MAX_SIZE    = 96
)

// ExecutionAddress represents a 20-byte Ethereum address
type ExecutionAddress [20]byte

// Verify implements the EIP-7980 signature verification
func Verify(signatureInfo []byte, payloadHash [32]byte) (ExecutionAddress, error) {
	if len(signatureInfo) != MAX_SIZE {
		return ExecutionAddress{}, ErrInvalidLength
	}

	signature := signatureInfo[:64]
	publicKey := signatureInfo[64:96]

	if !ed25519.Verify(publicKey, payloadHash[:], signature) {
		return ExecutionAddress{}, ErrInvalidSignature
	}

	return deriveAddress(publicKey), nil
}

// deriveAddress derives Ethereum address from Ed25519 public key
func deriveAddress(publicKey []byte) ExecutionAddress {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKey)
	fullHash := hash.Sum(nil)

	var address ExecutionAddress
	copy(address[:], fullHash[len(fullHash)-20:])
	return address
}

// Errors
var (
	ErrInvalidLength    = &VerifyError{"invalid signature length"}
	ErrInvalidSignature = &VerifyError{"signature verification failed"}
)

type VerifyError struct {
	msg string
}

func (e *VerifyError) Error() string {
	return e.msg
}

// TestValidSignature tests a valid Ed25519 signature
func TestValidSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	payloadHash := [32]byte{}
	copy(payloadHash[:], []byte("test transaction"))

	signature := ed25519.Sign(privateKey, payloadHash[:])

	signatureInfo := make([]byte, MAX_SIZE)
	copy(signatureInfo[:64], signature)
	copy(signatureInfo[64:], publicKey)

	address, err := Verify(signatureInfo, payloadHash)
	if err != nil {
		t.Errorf("Valid signature failed: %v", err)
	}

	if len(address) != 20 {
		t.Errorf("Address length = %d, want 20", len(address))
	}
}

// TestInvalidLength tests invalid signature length
func TestInvalidLength(t *testing.T) {
	signatureInfo := make([]byte, 50) // Wrong length
	payloadHash := [32]byte{}

	_, err := Verify(signatureInfo, payloadHash)
	if err != ErrInvalidLength {
		t.Errorf("Expected length error, got %v", err)
	}
}

// TestInvalidSignature tests an invalid signature
func TestInvalidSignature(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(nil)

	signatureInfo := make([]byte, MAX_SIZE)
	// Random/invalid signature
	copy(signatureInfo[64:], publicKey)

	payloadHash := [32]byte{}
	_, err := Verify(signatureInfo, payloadHash)

	if err != ErrInvalidSignature {
		t.Errorf("Expected signature error, got %v", err)
	}
}

// TestConstants verifies EIP-7980 constants
func TestConstants(t *testing.T) {
	if ALG_TYPE != 0x00 {
		t.Errorf("ALG_TYPE = %x, want 0x00", ALG_TYPE)
	}
	if GAS_PENALTY != 1000 {
		t.Errorf("GAS_PENALTY = %d, want 1000", GAS_PENALTY)
	}
	if MAX_SIZE != 96 {
		t.Errorf("MAX_SIZE = %d, want 96", MAX_SIZE)
	}
}

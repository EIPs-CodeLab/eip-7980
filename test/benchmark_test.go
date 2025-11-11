// test/benchmark_test.go
package test

import (
	"crypto/ed25519"
	"testing"
)

// BenchmarkVerify benchmarks the signature verification
func BenchmarkVerify(b *testing.B) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)

	payloadHash := [32]byte{}
	copy(payloadHash[:], []byte("benchmark payload"))

	signature := ed25519.Sign(privateKey, payloadHash[:])

	signatureInfo := make([]byte, MAX_SIZE)
	copy(signatureInfo[:64], signature)
	copy(signatureInfo[64:], publicKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Verify(signatureInfo, payloadHash)
	}
}

// BenchmarkAddressDerivation benchmarks address derivation
func BenchmarkAddressDerivation(b *testing.B) {
	publicKey, _, _ := ed25519.GenerateKey(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deriveAddress(publicKey)
	}
}

// BenchmarkEd25519Sign benchmarks Ed25519 signing
func BenchmarkEd25519Sign(b *testing.B) {
	_, privateKey, _ := ed25519.GenerateKey(nil)
	payloadHash := [32]byte{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(privateKey, payloadHash[:])
	}
}

// doc.go

/*
Package eip7980 implements EIP-7980: Ed25519 Transaction Signature Verification

EIP Details:
  - Number: 7980
  - Title: Adding Ed25519 as a signature scheme to test EIP-7932
  - Author: James Kempton (@SirSpudlington)
  - Status: Draft
  - Created: 2025-06-25
  - Requires: EIP-7932

Specification: https://eips.ethereum.org/EIPS/eip-7980
Discussion: https://ethereum-magicians.org/t/eip-7980-adding-ed25519-as-a-signature-scheme-to-test-eip-7932/24663

Overview:

EIP-7980 introduces Ed25519 signature verification for Ethereum transactions,
enabling cross-chain compatibility with ecosystems like Solana and Cosmos.

Constants:
  - ALG_TYPE: 0x00
  - GAS_PENALTY: 1000
  - MAX_SIZE: 96 bytes

Implementation:

This package provides a production-ready implementation of the EIP-7980
specification including:
  - Ed25519 signature verification (RFC 8032 Section 5.1.7)
  - Ethereum address derivation from Ed25519 public keys
  - Full test coverage and benchmarks

Usage:

	signatureInfo := make([]byte, 96) // 64-byte signature + 32-byte public key
	payloadHash := [32]byte{...}      // Transaction payload hash
	
	address, err := Verify(signatureInfo, payloadHash)
	if err != nil {
		// Handle verification failure
	}
*/
package main
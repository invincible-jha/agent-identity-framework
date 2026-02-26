// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

// Package types defines shared value types used across the agent-identity-framework.
package types

import "time"

// DIDMethod enumerates the supported Decentralized Identifier methods.
type DIDMethod string

const (
	DIDMethodWeb DIDMethod = "web"
	DIDMethodKey DIDMethod = "key"
)

// IdentityStatus represents the lifecycle state of an agent identity.
type IdentityStatus string

const (
	// StatusActive indicates the identity is valid and usable.
	StatusActive IdentityStatus = "active"
	// StatusExpired indicates the identity has passed its expiry time.
	StatusExpired IdentityStatus = "expired"
	// StatusRevoked indicates the identity has been explicitly revoked.
	StatusRevoked IdentityStatus = "revoked"
)

// KeyAlgorithm identifies the cryptographic algorithm used by a key pair.
type KeyAlgorithm string

const (
	KeyAlgorithmEd25519 KeyAlgorithm = "Ed25519"
)

// VerificationMethodType identifies the type of a DID verification method.
type VerificationMethodType string

const (
	VerificationMethodEd25519 VerificationMethodType = "Ed25519VerificationKey2020"
)

// ProofType identifies the type of a Linked Data Proof.
type ProofType string

const (
	ProofTypeEd25519Signature ProofType = "Ed25519Signature2020"
)

// SVIDType identifies whether an SVID is in x509 or JWT form.
type SVIDType string

const (
	SVIDTypeX509 SVIDType = "x509"
	SVIDTypeJWT  SVIDType = "jwt"
)

// KeyRotationReason documents why a key rotation was triggered.
type KeyRotationReason string

const (
	KeyRotationReasonScheduled  KeyRotationReason = "scheduled"
	KeyRotationReasonCompromise KeyRotationReason = "compromise"
	KeyRotationReasonExpiry     KeyRotationReason = "expiry"
)

// KeyRotationRecord captures metadata about a completed key rotation.
type KeyRotationRecord struct {
	PreviousKeyID string            `json:"previousKeyId"`
	NewKeyID      string            `json:"newKeyId"`
	Reason        KeyRotationReason `json:"reason"`
	RotatedAt     time.Time         `json:"rotatedAt"`
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 MuVeraAI Corporation

// Package attestation provides cryptographic agent attestation primitives.
//
// An attestation is a signed claim about an agent's identity, capabilities,
// trust level, or origin. Claims are signed by an Attestor using ECDSA P-256
// and can be independently verified by any party holding the attestor's
// public key.
//
// Claims can be bundled into an AttestationBundle for atomic verification:
// either all claims in the bundle are valid, or the entire bundle is rejected.
//
// # Trust Level Claims
//
// Trust levels in attestation claims are static values assigned by operators.
// There is no adaptive progression or behavioral scoring. A trust-level claim
// records the level an operator has manually assigned to an agent.
package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// ClaimType enumerates the types of claims that can be attested about an agent.
type ClaimType string

const (
	// ClaimIdentity attests that the agent is who it claims to be.
	ClaimIdentity ClaimType = "IDENTITY"
	// ClaimCapability attests that the agent possesses a specific capability.
	ClaimCapability ClaimType = "CAPABILITY"
	// ClaimTrustLevel attests the static trust level assigned to the agent by an operator.
	ClaimTrustLevel ClaimType = "TRUST_LEVEL"
	// ClaimOrigin attests the origin (deployment environment, organization) of the agent.
	ClaimOrigin ClaimType = "ORIGIN"
)

// AttestationClaim is a single signed assertion about an agent.
type AttestationClaim struct {
	// AgentID is the identifier of the agent this claim is about.
	AgentID string `json:"agentId"`
	// ClaimType identifies what aspect of the agent is being attested.
	ClaimType ClaimType `json:"claimType"`
	// Value is the claim payload (e.g. a trust level string, a capability name).
	Value string `json:"value"`
	// IssuedBy identifies the attestor that signed this claim.
	IssuedBy string `json:"issuedBy"`
	// IssuedAt is the UTC time when the claim was signed.
	IssuedAt time.Time `json:"issuedAt"`
	// Signature is the ECDSA P-256 signature over the canonical claim bytes.
	Signature []byte `json:"signature"`
}

// AttestationBundle is a collection of signed claims about a single agent.
// Verification is all-or-nothing: if any claim fails verification, the
// entire bundle is considered invalid.
type AttestationBundle struct {
	// AgentID is the agent all claims in this bundle pertain to.
	AgentID string `json:"agentId"`
	// Claims is the ordered list of attestation claims.
	Claims []*AttestationClaim `json:"claims"`
	// CreatedAt is the UTC time when the bundle was assembled.
	CreatedAt time.Time `json:"createdAt"`
}

// ---------------------------------------------------------------------------
// Attestor
// ---------------------------------------------------------------------------

// Attestor creates and signs attestation claims using an ECDSA P-256 key pair.
// The attestor's identity string is embedded in every claim's IssuedBy field.
type Attestor struct {
	// identity is the human-readable name or ID of this attestor.
	identity   string
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// NewAttestor constructs an Attestor with a freshly generated ECDSA P-256
// key pair and the given identity string.
func NewAttestor(identity string) (*Attestor, error) {
	if identity == "" {
		return nil, fmt.Errorf("attestation: identity must not be empty")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("attestation: generate ECDSA P-256 key: %w", err)
	}

	return &Attestor{
		identity:   identity,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// NewAttestorWithKey constructs an Attestor using an existing ECDSA P-256
// private key. The key's curve must be P-256.
func NewAttestorWithKey(identity string, privateKey *ecdsa.PrivateKey) (*Attestor, error) {
	if identity == "" {
		return nil, fmt.Errorf("attestation: identity must not be empty")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("attestation: privateKey must not be nil")
	}
	if privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("attestation: key must use P-256 curve")
	}

	return &Attestor{
		identity:   identity,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// PublicKey returns the attestor's ECDSA public key for verification.
func (a *Attestor) PublicKey() *ecdsa.PublicKey {
	return a.publicKey
}

// Identity returns the attestor's identity string.
func (a *Attestor) Identity() string {
	return a.identity
}

// CreateClaim signs and returns a new attestation claim for the given agent.
func (a *Attestor) CreateClaim(
	agentID string,
	claimType ClaimType,
	value string,
) (*AttestationClaim, error) {
	if agentID == "" {
		return nil, fmt.Errorf("attestation: agentID must not be empty")
	}
	if claimType == "" {
		return nil, fmt.Errorf("attestation: claimType must not be empty")
	}

	now := time.Now().UTC()

	claim := &AttestationClaim{
		AgentID:   agentID,
		ClaimType: claimType,
		Value:     value,
		IssuedBy:  a.identity,
		IssuedAt:  now,
	}

	// Compute the canonical bytes and sign them.
	canonical, err := canonicalizeClaim(claim)
	if err != nil {
		return nil, fmt.Errorf("attestation: canonicalize claim: %w", err)
	}

	digest := sha256.Sum256(canonical)
	r, s, err := ecdsa.Sign(rand.Reader, a.privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("attestation: sign claim: %w", err)
	}

	claim.Signature = encodeECDSASignature(r, s)
	return claim, nil
}

// CreateBundle assembles multiple claims into an AttestationBundle. All claims
// must pertain to the same agentID. The claims are not re-signed; they must
// have been created via CreateClaim first.
func (a *Attestor) CreateBundle(
	agentID string,
	claims ...*AttestationClaim,
) (*AttestationBundle, error) {
	if agentID == "" {
		return nil, fmt.Errorf("attestation: agentID must not be empty")
	}
	if len(claims) == 0 {
		return nil, fmt.Errorf("attestation: bundle must contain at least one claim")
	}

	for i, claim := range claims {
		if claim == nil {
			return nil, fmt.Errorf("attestation: claim at index %d is nil", i)
		}
		if claim.AgentID != agentID {
			return nil, fmt.Errorf(
				"attestation: claim at index %d has agentID %q, expected %q",
				i, claim.AgentID, agentID,
			)
		}
	}

	// Copy the claims slice to prevent external mutation.
	claimsCopy := make([]*AttestationClaim, len(claims))
	copy(claimsCopy, claims)

	return &AttestationBundle{
		AgentID:   agentID,
		Claims:    claimsCopy,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// VerifyClaim verifies the ECDSA signature on a single attestation claim
// using the provided public key.
func VerifyClaim(claim *AttestationClaim, pubKey *ecdsa.PublicKey) error {
	if claim == nil {
		return fmt.Errorf("attestation: claim must not be nil")
	}
	if pubKey == nil {
		return fmt.Errorf("attestation: public key must not be nil")
	}
	if len(claim.Signature) == 0 {
		return fmt.Errorf("attestation: claim has no signature")
	}

	canonical, err := canonicalizeClaim(claim)
	if err != nil {
		return fmt.Errorf("attestation: canonicalize claim for verification: %w", err)
	}

	digest := sha256.Sum256(canonical)
	r, s, err := decodeECDSASignature(claim.Signature)
	if err != nil {
		return fmt.Errorf("attestation: decode signature: %w", err)
	}

	if !ecdsa.Verify(pubKey, digest[:], r, s) {
		return fmt.Errorf("attestation: ECDSA signature verification failed for agent %q claim %s",
			claim.AgentID, claim.ClaimType)
	}

	return nil
}

// VerifyBundle verifies all claims in the bundle using the provided public key.
// Verification is all-or-nothing: if any single claim fails, the entire bundle
// is rejected and an error identifying the first failing claim is returned.
func VerifyBundle(bundle *AttestationBundle, pubKey *ecdsa.PublicKey) error {
	if bundle == nil {
		return fmt.Errorf("attestation: bundle must not be nil")
	}
	if pubKey == nil {
		return fmt.Errorf("attestation: public key must not be nil")
	}
	if len(bundle.Claims) == 0 {
		return fmt.Errorf("attestation: bundle contains no claims")
	}

	for i, claim := range bundle.Claims {
		if err := VerifyClaim(claim, pubKey); err != nil {
			return fmt.Errorf("attestation: bundle verification failed at claim %d: %w", i, err)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// claimCanonical is the structure used for deterministic JSON serialization
// of an attestation claim. The Signature field is excluded because it is
// the value being computed/verified.
type claimCanonical struct {
	AgentID   string    `json:"agentId"`
	ClaimType ClaimType `json:"claimType"`
	Value     string    `json:"value"`
	IssuedBy  string    `json:"issuedBy"`
	IssuedAt  string    `json:"issuedAt"`
}

// canonicalizeClaim produces the deterministic byte representation of a claim
// for signing and verification. The Signature field is excluded.
func canonicalizeClaim(claim *AttestationClaim) ([]byte, error) {
	canonical := claimCanonical{
		AgentID:   claim.AgentID,
		ClaimType: claim.ClaimType,
		Value:     claim.Value,
		IssuedBy:  claim.IssuedBy,
		IssuedAt:  claim.IssuedAt.Format(time.RFC3339Nano),
	}
	return json.Marshal(canonical)
}

// encodeECDSASignature concatenates the r and s integers into a 64-byte
// fixed-length encoding (32 bytes each for P-256).
func encodeECDSASignature(r, s *big.Int) []byte {
	const fieldSize = 32
	sig := make([]byte, fieldSize*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[fieldSize-len(rBytes):fieldSize], rBytes)
	copy(sig[fieldSize*2-len(sBytes):], sBytes)
	return sig
}

// decodeECDSASignature splits a 64-byte signature back into r and s values.
func decodeECDSASignature(sig []byte) (*big.Int, *big.Int, error) {
	const fieldSize = 32
	if len(sig) != fieldSize*2 {
		return nil, nil, fmt.Errorf("expected %d-byte signature, got %d", fieldSize*2, len(sig))
	}
	r := new(big.Int).SetBytes(sig[:fieldSize])
	s := new(big.Int).SetBytes(sig[fieldSize:])
	return r, s, nil
}

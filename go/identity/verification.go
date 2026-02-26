// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

package identity

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/aumos-ai/agent-identity-framework/types"
)

// VerificationResult is returned by IdentityManager.VerifyCredential.
type VerificationResult struct {
	// Valid is true when the credential's proof is cryptographically valid and the
	// credential has not expired.
	Valid bool
	// IssuerDID is the DID extracted from the credential's issuer field.
	IssuerDID string
	// SubjectID is the DID extracted from credentialSubject.id.
	SubjectID string
	// CredentialID is the VC's id field.
	CredentialID string
	// ExpiresAt is the parsed ExpirationDate, if present.
	ExpiresAt *time.Time
	// Reason is populated when Valid is false.
	Reason string
}

// CredentialVerifier resolves issuer DIDs and verifies Verifiable Credential proofs.
type CredentialVerifier struct {
	resolver *DIDResolver
}

// NewCredentialVerifier constructs a CredentialVerifier backed by the given DIDResolver.
func NewCredentialVerifier(resolver *DIDResolver) *CredentialVerifier {
	return &CredentialVerifier{resolver: resolver}
}

// VerifyCredential resolves the issuer's DID, extracts its public key, and verifies
// the credential's Ed25519 proof.
func (v *CredentialVerifier) VerifyCredential(ctx context.Context, vc *VerifiableCredential) (*VerificationResult, error) {
	if vc == nil {
		return nil, fmt.Errorf("verification: vc must not be nil")
	}
	if vc.Proof == nil {
		return &VerificationResult{
			Valid:        false,
			IssuerDID:   vc.Issuer,
			CredentialID: vc.ID,
			Reason:      "credential has no proof",
		}, nil
	}
	if vc.Proof.Type != string(types.ProofTypeEd25519Signature) {
		return &VerificationResult{
			Valid:        false,
			IssuerDID:   vc.Issuer,
			CredentialID: vc.ID,
			Reason:      fmt.Sprintf("unsupported proof type: %s", vc.Proof.Type),
		}, nil
	}

	// Check expiry before resolving DID to fail fast.
	var expiresAt *time.Time
	if vc.ExpirationDate != "" {
		parsed, err := time.Parse(time.RFC3339, vc.ExpirationDate)
		if err != nil {
			return &VerificationResult{
				Valid:        false,
				IssuerDID:   vc.Issuer,
				CredentialID: vc.ID,
				Reason:      fmt.Sprintf("parse ExpirationDate: %v", err),
			}, nil
		}
		expiresAt = &parsed
		if time.Now().UTC().After(parsed) {
			return &VerificationResult{
				Valid:        false,
				IssuerDID:   vc.Issuer,
				CredentialID: vc.ID,
				ExpiresAt:   expiresAt,
				Reason:      "credential has expired",
			}, nil
		}
	}

	// Resolve the issuer's DID document to get the public key.
	doc, err := v.resolver.Resolve(ctx, vc.Issuer)
	if err != nil {
		return nil, fmt.Errorf("verification: resolve issuer DID %s: %w", vc.Issuer, err)
	}

	publicKey, err := extractPublicKeyForVerification(doc, vc.Proof.VerificationMethod)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			IssuerDID:   vc.Issuer,
			CredentialID: vc.ID,
			ExpiresAt:   expiresAt,
			Reason:      fmt.Sprintf("extract public key: %v", err),
		}, nil
	}

	// Re-canonicalize the credential (without the proof) to get the signed bytes.
	canonical, err := canonicalize(vc)
	if err != nil {
		return nil, fmt.Errorf("verification: canonicalize credential: %w", err)
	}

	sig, err := ExtractSignatureBytes(vc.Proof)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			IssuerDID:   vc.Issuer,
			CredentialID: vc.ID,
			ExpiresAt:   expiresAt,
			Reason:      fmt.Sprintf("decode proof value: %v", err),
		}, nil
	}

	if !ed25519.Verify(publicKey, canonical, sig) {
		return &VerificationResult{
			Valid:        false,
			IssuerDID:   vc.Issuer,
			CredentialID: vc.ID,
			ExpiresAt:   expiresAt,
			Reason:      "Ed25519 signature is invalid",
		}, nil
	}

	subjectID, _ := extractSubjectID(vc.CredentialSubject)

	return &VerificationResult{
		Valid:        true,
		IssuerDID:   vc.Issuer,
		SubjectID:   subjectID,
		CredentialID: vc.ID,
		ExpiresAt:   expiresAt,
	}, nil
}

// extractPublicKeyForVerification finds the verification method matching vmID in a DID document
// and extracts the Ed25519 public key.
func extractPublicKeyForVerification(doc *DIDDocument, vmID string) (ed25519.PublicKey, error) {
	// If vmID is empty or a fragment of the DID, fall back to the first key.
	if vmID == "" || vmID == doc.ID {
		return ExtractPublicKeyFromDocument(doc)
	}

	for _, vm := range doc.VerificationMethod {
		if vm.ID == vmID || vm.ID == doc.ID+vmID {
			if vm.Type != string(types.VerificationMethodEd25519) {
				return nil, fmt.Errorf("verification method %s has unexpected type %s", vmID, vm.Type)
			}
			if vm.PublicKeyMultibase == "" {
				return nil, fmt.Errorf("verification method %s has no publicKeyMultibase", vmID)
			}
			return extractKeyFromMultibase(vm.PublicKeyMultibase)
		}
	}

	// Fall back to the first available key if no exact match.
	return ExtractPublicKeyFromDocument(doc)
}

// extractKeyFromMultibase decodes a multibase-encoded Ed25519 public key.
func extractKeyFromMultibase(encoded string) (ed25519.PublicKey, error) {
	doc := &DIDDocument{
		VerificationMethod: []VerificationMethod{{
			Type:               string(types.VerificationMethodEd25519),
			PublicKeyMultibase: encoded,
		}},
	}
	return ExtractPublicKeyFromDocument(doc)
}

// extractSubjectID retrieves the "id" field from a credentialSubject map.
func extractSubjectID(subject map[string]interface{}) (string, bool) {
	if subject == nil {
		return "", false
	}
	id, ok := subject["id"]
	if !ok {
		return "", false
	}
	s, ok := id.(string)
	return s, ok
}

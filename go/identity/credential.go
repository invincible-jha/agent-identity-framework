// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/aumos-ai/agent-identity-framework/types"
)

// VerifiableCredential is a W3C Verifiable Credential.
// Only generic W3C VC schemas are supported — no AumOS-specific schemas.
type VerifiableCredential struct {
	Context           []string               `json:"@context"`
	ID                string                 `json:"id"`
	Type              []string               `json:"type"`
	Issuer            string                 `json:"issuer"`
	IssuanceDate      string                 `json:"issuanceDate"`
	ExpirationDate    string                 `json:"expirationDate,omitempty"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Proof             *CredentialProof       `json:"proof,omitempty"`
}

// CredentialProof holds the Linked Data Proof attached to a VerifiableCredential.
type CredentialProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	// ProofValue is the base64url-encoded Ed25519 signature over the canonical credential bytes.
	ProofValue string `json:"proofValue"`
}

// IssueOptions carries parameters for CredentialIssuer.Issue.
type IssueOptions struct {
	// IssuerDID is the DID of the issuing agent or system. Required.
	IssuerDID string
	// SubjectID is the DID of the credential subject. Required.
	SubjectID string
	// CredentialType is appended to ["VerifiableCredential"] in the type array. Required.
	CredentialType string
	// Claims are the credential subject's claims. Required.
	Claims map[string]interface{}
	// TTL is how long the credential is valid. Defaults to 24h.
	TTL time.Duration
	// SigningKeyID is the KeyManager key ID to sign with. Required.
	SigningKeyID string
}

// Signer is satisfied by any key store that can sign arbitrary bytes.
// InMemoryKeyStore.Sign is a compatible implementation.
type Signer interface {
	Sign(ctx context.Context, keyID string, message []byte) ([]byte, error)
}

// CredentialIssuer creates and signs Verifiable Credentials.
type CredentialIssuer struct {
	signer Signer
}

// NewCredentialIssuer constructs a CredentialIssuer backed by the given Signer.
func NewCredentialIssuer(signer Signer) *CredentialIssuer {
	return &CredentialIssuer{signer: signer}
}

// Issue creates and signs a Verifiable Credential.
func (ci *CredentialIssuer) Issue(ctx context.Context, opts IssueOptions) (*VerifiableCredential, error) {
	if opts.IssuerDID == "" {
		return nil, fmt.Errorf("credential: IssuerDID must not be empty")
	}
	if opts.SubjectID == "" {
		return nil, fmt.Errorf("credential: SubjectID must not be empty")
	}
	if opts.CredentialType == "" {
		return nil, fmt.Errorf("credential: CredentialType must not be empty")
	}
	if opts.SigningKeyID == "" {
		return nil, fmt.Errorf("credential: SigningKeyID must not be empty")
	}
	if len(opts.Claims) == 0 {
		return nil, fmt.Errorf("credential: Claims must not be empty")
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	now := time.Now().UTC()
	subject := make(map[string]interface{}, len(opts.Claims)+1)
	subject["id"] = opts.SubjectID
	for k, v := range opts.Claims {
		subject[k] = v
	}

	vc := &VerifiableCredential{
		Context:  []string{"https://www.w3.org/2018/credentials/v1"},
		ID:       "urn:uuid:" + uuid.NewString(),
		Type:     []string{"VerifiableCredential", opts.CredentialType},
		Issuer:   opts.IssuerDID,
		IssuanceDate:   now.Format(time.RFC3339),
		ExpirationDate: now.Add(ttl).Format(time.RFC3339),
		CredentialSubject: subject,
	}

	// Compute signature over the credential without the proof field.
	canonical, err := canonicalize(vc)
	if err != nil {
		return nil, fmt.Errorf("credential: canonicalize: %w", err)
	}

	sig, err := ci.signer.Sign(ctx, opts.SigningKeyID, canonical)
	if err != nil {
		return nil, fmt.Errorf("credential: sign: %w", err)
	}

	vmID := opts.IssuerDID + "#key-1"
	vc.Proof = &CredentialProof{
		Type:               string(types.ProofTypeEd25519Signature),
		Created:            now.Format(time.RFC3339),
		VerificationMethod: vmID,
		ProofPurpose:       "assertionMethod",
		ProofValue:         base64.RawURLEncoding.EncodeToString(sig),
	}

	return vc, nil
}

// canonicalize returns the deterministic JSON representation of a VC without its proof.
// This is the byte sequence that is signed and must be verified.
func canonicalize(vc *VerifiableCredential) ([]byte, error) {
	// Shallow copy omitting the proof to get the canonical form.
	type vcWithoutProof struct {
		Context           []string               `json:"@context"`
		ID                string                 `json:"id"`
		Type              []string               `json:"type"`
		Issuer            string                 `json:"issuer"`
		IssuanceDate      string                 `json:"issuanceDate"`
		ExpirationDate    string                 `json:"expirationDate,omitempty"`
		CredentialSubject map[string]interface{} `json:"credentialSubject"`
	}
	canonical := vcWithoutProof{
		Context:           vc.Context,
		ID:                vc.ID,
		Type:              vc.Type,
		Issuer:            vc.Issuer,
		IssuanceDate:      vc.IssuanceDate,
		ExpirationDate:    vc.ExpirationDate,
		CredentialSubject: vc.CredentialSubject,
	}
	return json.Marshal(canonical)
}

// ExtractSignatureBytes decodes the base64url ProofValue from a CredentialProof.
func ExtractSignatureBytes(proof *CredentialProof) ([]byte, error) {
	if proof == nil {
		return nil, fmt.Errorf("credential: proof is nil")
	}
	sig, err := base64.RawURLEncoding.DecodeString(proof.ProofValue)
	if err != nil {
		return nil, fmt.Errorf("credential: decode ProofValue: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("credential: unexpected signature length %d", len(sig))
	}
	return sig, nil
}

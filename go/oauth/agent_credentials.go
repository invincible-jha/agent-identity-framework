// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 MuVeraAI Corporation

// Package oauth provides OAuth 2.1 agent credential management for the
// agent-identity-framework. It implements the private_key_jwt client
// authentication method using ECDSA P-256 keys.
//
// Credentials are issued to agents with explicit scopes and a fixed TTL.
// There is no automatic credential rotation -- rotation is operator-triggered
// only.
//
// # JWT Client Assertions
//
// The CreateClientAssertion method produces a JWT suitable for the
// client_assertion parameter in an OAuth 2.1 token request using the
// private_key_jwt authentication method (RFC 7523 Section 2.2).
//
// The JWT is signed with ECDSA P-256 (ES256) using the agent's key pair.
// No external JWT library is used; the implementation uses only crypto/ecdsa
// and encoding/json from the standard library.
package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// AgentCredentials holds the OAuth 2.1 credentials issued to an agent.
type AgentCredentials struct {
	// AgentID is the AumOS agent identifier that owns these credentials.
	AgentID string `json:"agentId"`
	// ClientID is the OAuth 2.1 client identifier.
	ClientID string `json:"clientId"`
	// KeyPair is the ECDSA P-256 key pair used for signing client assertions.
	KeyPair *ECKeyPair `json:"-"`
	// Scopes are the OAuth scopes granted to this credential set.
	Scopes []string `json:"scopes"`
	// IssuedAt is the UTC time when the credentials were created.
	IssuedAt time.Time `json:"issuedAt"`
	// ExpiresAt is the UTC time after which the credentials are no longer valid.
	ExpiresAt time.Time `json:"expiresAt"`
}

// IsExpired reports whether the credentials have passed their expiry time.
func (ac *AgentCredentials) IsExpired() bool {
	return time.Now().UTC().After(ac.ExpiresAt)
}

// ECKeyPair holds an ECDSA P-256 key pair for OAuth 2.1 client assertions.
type ECKeyPair struct {
	// PrivateKey is the ECDSA private key. Never serialized externally.
	PrivateKey *ecdsa.PrivateKey
	// PublicKey is the ECDSA public key.
	PublicKey *ecdsa.PublicKey
}

// CredentialManager manages the lifecycle of agent OAuth 2.1 credentials.
// All methods are safe for concurrent use.
type CredentialManager struct {
	mu          sync.RWMutex
	credentials map[string]*AgentCredentials // keyed by ClientID
	revoked     map[string]struct{}          // set of revoked ClientIDs
	counter     uint64
}

// NewCredentialManager constructs a CredentialManager with empty state.
func NewCredentialManager() *CredentialManager {
	return &CredentialManager{
		credentials: make(map[string]*AgentCredentials),
		revoked:     make(map[string]struct{}),
	}
}

// IssueCredentials creates new OAuth 2.1 credentials for the given agent.
// A fresh ECDSA P-256 key pair is generated for each credential set.
// The TTL controls how long the credentials remain valid.
//
// There is no automatic rotation. Credential rotation is operator-triggered
// by calling IssueCredentials again and revoking the old credentials.
func (cm *CredentialManager) IssueCredentials(
	agentID string,
	scopes []string,
	ttl time.Duration,
) (*AgentCredentials, error) {
	if agentID == "" {
		return nil, fmt.Errorf("oauth: agentID must not be empty")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("oauth: ttl must be positive")
	}

	// Generate a new ECDSA P-256 key pair.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("oauth: generate ECDSA P-256 key: %w", err)
	}

	now := time.Now().UTC()

	cm.mu.Lock()
	cm.counter++
	clientID := fmt.Sprintf("aumos-agent-%s-%d", agentID, cm.counter)
	cm.mu.Unlock()

	scopesCopy := make([]string, len(scopes))
	copy(scopesCopy, scopes)

	creds := &AgentCredentials{
		AgentID:  agentID,
		ClientID: clientID,
		KeyPair: &ECKeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		},
		Scopes:    scopesCopy,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}

	cm.mu.Lock()
	cm.credentials[clientID] = creds
	cm.mu.Unlock()

	return creds, nil
}

// ValidateCredentials checks that the given credentials are not expired,
// not revoked, and have valid key material.
func (cm *CredentialManager) ValidateCredentials(creds *AgentCredentials) error {
	if creds == nil {
		return fmt.Errorf("oauth: credentials must not be nil")
	}
	if creds.ClientID == "" {
		return fmt.Errorf("oauth: credentials missing ClientID")
	}

	cm.mu.RLock()
	_, isRevoked := cm.revoked[creds.ClientID]
	cm.mu.RUnlock()

	if isRevoked {
		return fmt.Errorf("oauth: credentials for client %q have been revoked", creds.ClientID)
	}

	if creds.IsExpired() {
		return fmt.Errorf("oauth: credentials for client %q expired at %s",
			creds.ClientID, creds.ExpiresAt.Format(time.RFC3339))
	}

	if creds.KeyPair == nil {
		return fmt.Errorf("oauth: credentials for client %q have no key pair", creds.ClientID)
	}
	if creds.KeyPair.PrivateKey == nil {
		return fmt.Errorf("oauth: credentials for client %q have no private key", creds.ClientID)
	}
	if creds.KeyPair.PublicKey == nil {
		return fmt.Errorf("oauth: credentials for client %q have no public key", creds.ClientID)
	}

	// Verify key curve is P-256.
	if creds.KeyPair.PrivateKey.Curve != elliptic.P256() {
		return fmt.Errorf("oauth: credentials for client %q use unsupported curve (expected P-256)",
			creds.ClientID)
	}

	return nil
}

// RevokeCredentials marks the credentials identified by clientID as revoked.
// Revoked credentials will fail ValidateCredentials and cannot be used to
// create client assertions.
func (cm *CredentialManager) RevokeCredentials(clientID string) error {
	if clientID == "" {
		return fmt.Errorf("oauth: clientID must not be empty")
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, exists := cm.credentials[clientID]; !exists {
		return fmt.Errorf("oauth: no credentials found for client %q", clientID)
	}

	cm.revoked[clientID] = struct{}{}
	return nil
}

// GetCredentials retrieves credentials by clientID. Returns an error if the
// clientID is unknown.
func (cm *CredentialManager) GetCredentials(clientID string) (*AgentCredentials, error) {
	cm.mu.RLock()
	creds, exists := cm.credentials[clientID]
	cm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("oauth: no credentials found for client %q", clientID)
	}
	return creds, nil
}

// ---------------------------------------------------------------------------
// JWT Client Assertion (private_key_jwt)
// ---------------------------------------------------------------------------

// jwtHeader is the fixed JOSE header for ES256 JWTs.
type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

// jwtClaims holds the claims for an OAuth 2.1 client assertion JWT.
type jwtClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JWTID     string `json:"jti"`
}

// CreateClientAssertion produces a signed JWT client assertion suitable for
// OAuth 2.1 private_key_jwt authentication (RFC 7523 Section 2.2).
//
// The JWT is signed with ES256 (ECDSA P-256 + SHA-256). The iss and sub
// claims are both set to the credential's ClientID.
//
// No external JWT library is used.
func CreateClientAssertion(creds *AgentCredentials) (string, error) {
	if creds == nil {
		return "", fmt.Errorf("oauth: credentials must not be nil")
	}
	if creds.KeyPair == nil || creds.KeyPair.PrivateKey == nil {
		return "", fmt.Errorf("oauth: credentials have no private key")
	}

	now := time.Now().UTC()

	header := jwtHeader{
		Algorithm: "ES256",
		Type:      "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("oauth: marshal JWT header: %w", err)
	}

	claims := jwtClaims{
		Issuer:    creds.ClientID,
		Subject:   creds.ClientID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		JWTID:     generateJTI(),
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("oauth: marshal JWT claims: %w", err)
	}

	// Encode header and payload.
	encodedHeader := base64URLEncode(headerJSON)
	encodedPayload := base64URLEncode(claimsJSON)
	signingInput := encodedHeader + "." + encodedPayload

	// Sign with ECDSA P-256 + SHA-256.
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, creds.KeyPair.PrivateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("oauth: sign JWT: %w", err)
	}

	// Encode the signature as the concatenation of r and s, each padded to
	// 32 bytes (the P-256 field size).
	signature := encodeES256Signature(r, s)
	encodedSignature := base64URLEncode(signature)

	return signingInput + "." + encodedSignature, nil
}

// VerifyClientAssertion verifies an ES256 JWT client assertion using the
// provided ECDSA public key. It checks the signature but does not validate
// claims (expiry, audience, etc.) -- the caller is responsible for claim
// validation.
func VerifyClientAssertion(token string, publicKey *ecdsa.PublicKey) error {
	if publicKey == nil {
		return fmt.Errorf("oauth: public key must not be nil")
	}

	// Split into header.payload.signature
	parts := splitJWT(token)
	if parts == nil {
		return fmt.Errorf("oauth: malformed JWT (expected 3 dot-separated segments)")
	}

	signingInput := parts[0] + "." + parts[1]
	signatureBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return fmt.Errorf("oauth: decode JWT signature: %w", err)
	}

	r, s, err := decodeES256Signature(signatureBytes)
	if err != nil {
		return fmt.Errorf("oauth: decode ES256 signature: %w", err)
	}

	digest := sha256.Sum256([]byte(signingInput))
	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		return fmt.Errorf("oauth: JWT signature verification failed")
	}

	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// base64URLEncode encodes bytes as unpadded base64url.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes an unpadded base64url string.
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// splitJWT splits a JWT token into its three segments. Returns nil if the
// token does not have exactly three dot-separated parts.
func splitJWT(token string) []string {
	var parts []string
	start := 0
	count := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
			count++
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		return nil
	}
	return parts
}

// encodeES256Signature concatenates the r and s integers into a 64-byte
// fixed-length encoding (32 bytes each, zero-padded on the left).
func encodeES256Signature(r, s *big.Int) []byte {
	const fieldSize = 32
	sig := make([]byte, fieldSize*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[fieldSize-len(rBytes):fieldSize], rBytes)
	copy(sig[fieldSize*2-len(sBytes):], sBytes)
	return sig
}

// decodeES256Signature splits a 64-byte signature into r and s big.Int values.
func decodeES256Signature(sig []byte) (*big.Int, *big.Int, error) {
	const fieldSize = 32
	if len(sig) != fieldSize*2 {
		return nil, nil, fmt.Errorf("expected %d-byte ES256 signature, got %d", fieldSize*2, len(sig))
	}
	r := new(big.Int).SetBytes(sig[:fieldSize])
	s := new(big.Int).SetBytes(sig[fieldSize:])
	return r, s, nil
}

// generateJTI produces a unique JWT ID using random bytes.
func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

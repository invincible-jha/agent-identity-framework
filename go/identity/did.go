// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

package identity

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/multiformats/go-multibase"

	"github.com/aumos-ai/agent-identity-framework/types"
)

// ed25519MulticodecPrefix is the multicodec varint prefix for Ed25519 public keys (0xed01).
var ed25519MulticodecPrefix = []byte{0xed, 0x01}

// DIDDocument represents a W3C DID Document.
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication"`
	AssertionMethod    []string             `json:"assertionMethod"`
	Created            string               `json:"created,omitempty"`
	Updated            string               `json:"updated,omitempty"`
}

// VerificationMethod is an entry in a DID Document's verificationMethod array.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// DeriveKeyDID creates a did:key DID from an Ed25519 public key.
// The key is encoded as multibase base58btc with the 0xed01 multicodec prefix.
func DeriveKeyDID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("did: invalid Ed25519 public key length %d", len(publicKey))
	}

	// Prepend the multicodec prefix before encoding.
	prefixed := append(ed25519MulticodecPrefix, publicKey...)

	encoded, err := multibase.Encode(multibase.Base58BTC, prefixed)
	if err != nil {
		return "", fmt.Errorf("did: multibase encode: %w", err)
	}

	return "did:key:" + encoded, nil
}

// DeriveWebDID constructs a did:web DID for the given host, optional path, and agent ID.
// The resulting DID follows the did:web specification:
//
//	did:web:<host>:<path-segment>:<agentID>
//
// If path is empty only the host and agentID are used.
func DeriveWebDID(host, path, agentID string) string {
	host = strings.ReplaceAll(host, "/", ":")
	if path == "" {
		return fmt.Sprintf("did:web:%s:%s", host, agentID)
	}
	path = strings.Trim(path, "/")
	path = strings.ReplaceAll(path, "/", ":")
	return fmt.Sprintf("did:web:%s:%s:%s", host, path, agentID)
}

// BuildDIDDocument constructs a DID Document for the given DID and public key.
func BuildDIDDocument(did string, publicKey ed25519.PublicKey) (*DIDDocument, error) {
	encoded, err := multibase.Encode(multibase.Base58BTC, publicKey)
	if err != nil {
		return nil, fmt.Errorf("did: encode public key: %w", err)
	}

	vmID := did + "#key-1"
	now := time.Now().UTC().Format(time.RFC3339)

	return &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID: did,
		VerificationMethod: []VerificationMethod{
			{
				ID:                 vmID,
				Type:               string(types.VerificationMethodEd25519),
				Controller:         did,
				PublicKeyMultibase: encoded,
			},
		},
		Authentication:  []string{vmID},
		AssertionMethod: []string{vmID},
		Created:         now,
		Updated:         now,
	}, nil
}

// ParseDIDMethod extracts the method string from a DID (e.g. "key" from "did:key:...").
func ParseDIDMethod(did string) (types.DIDMethod, error) {
	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 || parts[0] != "did" {
		return "", &types.ErrInvalidDID{DID: did, Reason: "must start with 'did:'"}
	}
	switch parts[1] {
	case "key":
		return types.DIDMethodKey, nil
	case "web":
		return types.DIDMethodWeb, nil
	default:
		return "", &types.ErrUnsupportedDIDMethod{Method: parts[1]}
	}
}

// ExtractPublicKeyFromKeyDID decodes the Ed25519 public key embedded in a did:key DID.
func ExtractPublicKeyFromKeyDID(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, "did:key:") {
		return nil, &types.ErrInvalidDID{DID: did, Reason: "not a did:key DID"}
	}

	encoded := strings.TrimPrefix(did, "did:key:")

	_, decoded, err := multibase.Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("did: multibase decode: %w", err)
	}

	if len(decoded) < len(ed25519MulticodecPrefix) {
		return nil, &types.ErrInvalidDID{DID: did, Reason: "decoded bytes too short"}
	}

	// Verify the multicodec prefix.
	for i, b := range ed25519MulticodecPrefix {
		if decoded[i] != b {
			return nil, &types.ErrInvalidDID{DID: did, Reason: "unexpected multicodec prefix"}
		}
	}

	rawKey := decoded[len(ed25519MulticodecPrefix):]
	if len(rawKey) != ed25519.PublicKeySize {
		return nil, &types.ErrInvalidDID{DID: did, Reason: fmt.Sprintf("expected %d key bytes, got %d", ed25519.PublicKeySize, len(rawKey))}
	}

	return ed25519.PublicKey(rawKey), nil
}

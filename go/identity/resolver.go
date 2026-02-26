// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/multiformats/go-multibase"

	"github.com/aumos-ai/agent-identity-framework/types"
)

// ResolverOptions configures a DIDResolver.
type ResolverOptions struct {
	// HTTPClient is used for did:web resolution. Defaults to a client with a 10s timeout.
	HTTPClient *http.Client
	// MaxResponseBytes caps the size of a fetched DID Document (default 1 MiB).
	MaxResponseBytes int64
}

// DIDResolver resolves DID Documents for did:web and did:key methods.
// For did:key, resolution is entirely local (no network call).
// For did:web, the document is fetched via HTTPS.
type DIDResolver struct {
	httpClient       *http.Client
	maxResponseBytes int64
}

// NewDIDResolver constructs a DIDResolver with the provided options.
func NewDIDResolver(opts ResolverOptions) *DIDResolver {
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	maxBytes := opts.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20 // 1 MiB
	}
	return &DIDResolver{
		httpClient:       client,
		maxResponseBytes: maxBytes,
	}
}

// Resolve returns the DID Document for the given DID.
func (r *DIDResolver) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
	method, err := ParseDIDMethod(did)
	if err != nil {
		return nil, fmt.Errorf("resolver: parse DID method: %w", err)
	}

	switch method {
	case types.DIDMethodKey:
		return r.resolveKey(did)
	case types.DIDMethodWeb:
		return r.resolveWeb(ctx, did)
	default:
		return nil, &types.ErrUnsupportedDIDMethod{Method: string(method)}
	}
}

// resolveKey synthesizes a DID Document from the public key encoded in a did:key.
func (r *DIDResolver) resolveKey(did string) (*DIDDocument, error) {
	publicKey, err := ExtractPublicKeyFromKeyDID(did)
	if err != nil {
		return nil, fmt.Errorf("resolver: extract key from did:key: %w", err)
	}
	doc, err := BuildDIDDocument(did, publicKey)
	if err != nil {
		return nil, fmt.Errorf("resolver: build DID document: %w", err)
	}
	return doc, nil
}

// resolveWeb fetches the DID Document from the well-known HTTPS URL for a did:web.
// did:web:example.com  =>  https://example.com/.well-known/did.json
// did:web:example.com:agents:abc  =>  https://example.com/agents/abc/did.json
func (r *DIDResolver) resolveWeb(ctx context.Context, did string) (*DIDDocument, error) {
	url, err := webDIDToURL(did)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &types.ErrDIDResolutionFailed{DID: did, Reason: fmt.Sprintf("build request: %v", err)}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, &types.ErrDIDResolutionFailed{DID: did, Reason: fmt.Sprintf("HTTP fetch: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &types.ErrDIDResolutionFailed{DID: did, Reason: fmt.Sprintf("HTTP %d from %s", resp.StatusCode, url)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, r.maxResponseBytes))
	if err != nil {
		return nil, &types.ErrDIDResolutionFailed{DID: did, Reason: fmt.Sprintf("read body: %v", err)}
	}

	var doc DIDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, &types.ErrDIDResolutionFailed{DID: did, Reason: fmt.Sprintf("parse JSON: %v", err)}
	}

	if doc.ID != did {
		return nil, &types.ErrDIDResolutionFailed{DID: did, Reason: fmt.Sprintf("document ID %q does not match requested DID", doc.ID)}
	}

	return &doc, nil
}

// webDIDToURL converts a did:web DID string to the canonical HTTPS URL for its DID Document.
func webDIDToURL(did string) (string, error) {
	withoutScheme := strings.TrimPrefix(did, "did:web:")
	if withoutScheme == "" {
		return "", &types.ErrInvalidDID{DID: did, Reason: "empty did:web host"}
	}

	// Colons in the method-specific identifier (after the host) become path separators.
	// Percent-encoded colons in the host are decoded per the did:web spec.
	parts := strings.SplitN(withoutScheme, ":", 2)
	host := strings.ReplaceAll(parts[0], "%3A", ":")

	if len(parts) == 1 {
		// No path: https://host/.well-known/did.json
		return fmt.Sprintf("https://%s/.well-known/did.json", host), nil
	}

	// Path segments: colon-separated become slash-separated
	pathPart := strings.ReplaceAll(parts[1], ":", "/")
	return fmt.Sprintf("https://%s/%s/did.json", host, pathPart), nil
}

// ExtractPublicKeyFromDocument extracts the first Ed25519VerificationKey2020 from a DID Document.
func ExtractPublicKeyFromDocument(doc *DIDDocument) (ed25519.PublicKey, error) {
	for _, vm := range doc.VerificationMethod {
		if vm.Type != string(types.VerificationMethodEd25519) {
			continue
		}
		if vm.PublicKeyMultibase == "" {
			continue
		}

		_, decoded, err := multibase.Decode(vm.PublicKeyMultibase)
		if err != nil {
			return nil, fmt.Errorf("resolver: decode publicKeyMultibase: %w", err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("resolver: unexpected key length %d", len(decoded))
		}
		return ed25519.PublicKey(decoded), nil
	}
	return nil, fmt.Errorf("resolver: no Ed25519VerificationKey2020 found in DID document for %s", doc.ID)
}

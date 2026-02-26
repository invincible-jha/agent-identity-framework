// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

// did_resolution demonstrates resolving both did:key (local) and did:web (HTTP)
// DIDs and extracting their public keys.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/aumos-ai/agent-identity-framework/identity"
)

func main() {
	ctx := context.Background()

	// --- 1. Resolve a did:key DID (no network required) ---

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("GenerateKey: %v", err)
	}

	did, err := identity.DeriveKeyDID(pub)
	if err != nil {
		log.Fatalf("DeriveKeyDID: %v", err)
	}
	fmt.Printf("Generated did:key: %s\n\n", did)

	resolver := identity.NewDIDResolver(identity.ResolverOptions{})

	doc, err := resolver.Resolve(ctx, did)
	if err != nil {
		log.Fatalf("Resolve did:key: %v", err)
	}

	fmt.Println("=== Resolved did:key Document ===")
	docJSON, _ := json.MarshalIndent(doc, "", "  ")
	fmt.Println(string(docJSON))
	fmt.Println()

	extractedKey, err := identity.ExtractPublicKeyFromDocument(doc)
	if err != nil {
		log.Fatalf("ExtractPublicKeyFromDocument: %v", err)
	}
	fmt.Printf("Public key match: %v\n\n", pub.Equal(extractedKey))

	// --- 2. Resolve a did:web DID via a test HTTP server ---

	// Construct the DID document we will serve.
	webDID := "did:web:localhost:agents:demo-agent-1"
	webDoc, err := identity.BuildDIDDocument(webDID, pub)
	if err != nil {
		log.Fatalf("BuildDIDDocument: %v", err)
	}

	// Spin up a test HTTP server that serves the DID document.
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(webDoc)
	}))
	defer testServer.Close()

	// Override the resolver's HTTP client to point to our test server.
	customClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &rewriteTransport{
			baseURL:    testServer.URL,
			underlying: http.DefaultTransport,
		},
	}

	webResolver := identity.NewDIDResolver(identity.ResolverOptions{
		HTTPClient: customClient,
	})

	resolvedWebDoc, err := webResolver.Resolve(ctx, webDID)
	if err != nil {
		log.Fatalf("Resolve did:web: %v", err)
	}

	fmt.Println("=== Resolved did:web Document ===")
	webDocJSON, _ := json.MarshalIndent(resolvedWebDoc, "", "  ")
	fmt.Println(string(webDocJSON))
	fmt.Println()

	webKey, err := identity.ExtractPublicKeyFromDocument(resolvedWebDoc)
	if err != nil {
		log.Fatalf("ExtractPublicKeyFromDocument (web): %v", err)
	}
	fmt.Printf("Public key match (web): %v\n", pub.Equal(webKey))
}

// rewriteTransport redirects all requests to a base URL for testing.
type rewriteTransport struct {
	baseURL    string
	underlying http.RoundTripper
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	req.URL.Host = t.baseURL[7:] // strip "http://"
	return t.underlying.RoundTrip(req)
}

// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

// did_key_example demonstrates working with did:key identities in the
// agent-identity-framework. It shows how to:
//   - Create an agent with a did:key DID
//   - Derive and inspect the encoded DID string
//   - Resolve the DID Document locally (no network call required for did:key)
//   - Extract the public key from a did:key DID
//   - Verify the round-trip: key → DID → document → key
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"time"

	"github.com/aumos-ai/agent-identity-framework/identity"
	"github.com/aumos-ai/agent-identity-framework/types"
)

func main() {
	ctx := context.Background()

	// Step 1: Create an IdentityManager and issue a did:key identity.
	//
	// did:key encodes the Ed25519 public key directly into the DID string using
	// multibase base58btc with the 0xed01 multicodec prefix. Resolution is
	// entirely local — no network round-trip is needed.
	store := identity.NewInMemoryStore()
	manager, err := identity.NewIdentityManager(identity.ManagerOptions{
		Store:      store,
		DefaultTTL: 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("NewIdentityManager: %v", err)
	}

	agentIdentity, err := manager.CreateIdentity(ctx, identity.CreateOptions{
		OwnerDID:  "did:web:acme.example:owner",
		DIDMethod: types.DIDMethodKey,
	})
	if err != nil {
		log.Fatalf("CreateIdentity: %v", err)
	}

	fmt.Printf("Agent DID (did:key): %s\n\n", agentIdentity.DID)

	// Step 2: Resolve the DID Document.
	//
	// NewDIDResolver can handle both did:key (local) and did:web (HTTP fetch).
	// For did:key the resolver synthesises the DID Document from the public key
	// embedded in the DID string — no external service is contacted.
	resolver := identity.NewDIDResolver(identity.ResolverOptions{})

	doc, err := resolver.Resolve(ctx, agentIdentity.DID)
	if err != nil {
		log.Fatalf("Resolve: %v", err)
	}

	fmt.Printf("DID Document\n")
	fmt.Printf("  ID:      %s\n", doc.ID)
	fmt.Printf("  Context: %v\n", doc.Context)
	fmt.Printf("  Verification methods: %d\n", len(doc.VerificationMethod))
	if len(doc.VerificationMethod) > 0 {
		vm := doc.VerificationMethod[0]
		fmt.Printf("    [0] ID:   %s\n", vm.ID)
		fmt.Printf("    [0] Type: %s\n", vm.Type)
		fmt.Printf("    [0] Key:  %s\n", vm.PublicKeyMultibase)
	}
	fmt.Printf("  Authentication:  %v\n", doc.Authentication)
	fmt.Printf("  AssertionMethod: %v\n\n", doc.AssertionMethod)

	// Step 3: Extract the public key from the DID string.
	//
	// ExtractPublicKeyFromKeyDID decodes the multibase-encoded key bytes
	// directly from the DID without needing to build a full DID Document.
	extractedKey, err := identity.ExtractPublicKeyFromKeyDID(agentIdentity.DID)
	if err != nil {
		log.Fatalf("ExtractPublicKeyFromKeyDID: %v", err)
	}

	fmt.Printf("Extracted public key length: %d bytes\n", len(extractedKey))

	// Step 4: Verify the round-trip — extracted key must match the stored key.
	//
	// This confirms that the DID faithfully encodes the public key and that
	// both the agent's key store and the DID string agree on the key material.
	storedKey := agentIdentity.PublicKey
	keysMatch := ed25519.PublicKey(extractedKey).Equal(storedKey)
	fmt.Printf("Round-trip key match (DID → extract → compare): %v\n\n", keysMatch)

	if !keysMatch {
		log.Fatal("key round-trip failed — DID does not encode the expected public key")
	}

	// Step 5: Parse the DID method from an arbitrary DID string.
	method, err := identity.ParseDIDMethod(agentIdentity.DID)
	if err != nil {
		log.Fatalf("ParseDIDMethod: %v", err)
	}
	fmt.Printf("DID method: %s (expected: %s)\n", method, types.DIDMethodKey)

	// Step 6: Build a DID Document from scratch using the stored public key.
	//
	// BuildDIDDocument is useful when you need to serve your own DID Document
	// from a did:web endpoint and want to ensure it matches the agent's did:key.
	builtDoc, err := identity.BuildDIDDocument(agentIdentity.DID, agentIdentity.PublicKey)
	if err != nil {
		log.Fatalf("BuildDIDDocument: %v", err)
	}
	fmt.Printf("Built DID Document ID: %s\n", builtDoc.ID)
	fmt.Printf("Document IDs match: %v\n", builtDoc.ID == doc.ID)
}

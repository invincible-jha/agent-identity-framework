// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

// basic_identity demonstrates creating and managing agent identities using the
// agent-identity-framework. It shows how to:
//   - Construct an IdentityManager with an in-memory store
//   - Create a new agent identity (generates an Ed25519 key pair and a did:key DID)
//   - Resolve the identity back from the store by DID
//   - List all identities in the store
//   - Revoke an identity and confirm the status change
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aumos-ai/agent-identity-framework/identity"
	"github.com/aumos-ai/agent-identity-framework/types"
)

func main() {
	ctx := context.Background()

	// Step 1: Build an IdentityManager backed by an in-memory store.
	//
	// The store holds AgentIdentity records for the lifetime of this process.
	// For a durable deployment, swap InMemoryStore for a database-backed implementation.
	store := identity.NewInMemoryStore()
	manager, err := identity.NewIdentityManager(identity.ManagerOptions{
		Store:      store,
		DefaultTTL: 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("NewIdentityManager: %v", err)
	}

	// Step 2: Create an agent identity.
	//
	// CreateIdentity generates an Ed25519 key pair, derives a did:key DID from the
	// public key, and persists the AgentIdentity record in the store.
	ownerDID := "did:web:example.com:owner"
	agentIdentity, err := manager.CreateIdentity(ctx, identity.CreateOptions{
		OwnerDID:  ownerDID,
		TTL:       8 * time.Hour,
		DIDMethod: types.DIDMethodKey,
	})
	if err != nil {
		log.Fatalf("CreateIdentity: %v", err)
	}

	fmt.Printf("Created agent identity\n")
	fmt.Printf("  DID:       %s\n", agentIdentity.DID)
	fmt.Printf("  Owner:     %s\n", agentIdentity.OwnerDID)
	fmt.Printf("  Status:    %s\n", agentIdentity.Status)
	fmt.Printf("  Created:   %s\n", agentIdentity.CreatedAt.Format(time.RFC3339))
	fmt.Printf("  Expires:   %s\n", agentIdentity.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("  Key ID:    %s\n", agentIdentity.ActiveKeyID)
	fmt.Printf("  Valid:     %v\n\n", agentIdentity.IsValid())

	// Step 3: Resolve the identity by DID.
	//
	// ResolveIdentity checks that the identity is active and not expired before
	// returning it. Use this whenever you need to verify an agent's current state.
	resolved, err := manager.ResolveIdentity(ctx, agentIdentity.DID)
	if err != nil {
		log.Fatalf("ResolveIdentity: %v", err)
	}
	fmt.Printf("Resolved identity by DID: %s\n", resolved.DID)
	fmt.Printf("  Status matches: %v\n\n", resolved.Status == types.StatusActive)

	// Step 4: Create a second identity so we have more than one to list.
	secondIdentity, err := manager.CreateIdentity(ctx, identity.CreateOptions{
		OwnerDID:  ownerDID,
		TTL:       2 * time.Hour,
		DIDMethod: types.DIDMethodKey,
	})
	if err != nil {
		log.Fatalf("CreateIdentity (second): %v", err)
	}
	fmt.Printf("Created second identity: %s\n\n", secondIdentity.DID)

	// Step 5: List all identities.
	//
	// The store returns all AgentIdentity records without filtering.
	// Apply application-level filters as needed.
	all, err := manager.Store().List(ctx)
	if err != nil {
		log.Fatalf("List: %v", err)
	}
	fmt.Printf("All identities in store (%d total):\n", len(all))
	for i, id := range all {
		fmt.Printf("  [%d] %s — status=%s\n", i+1, id.DID, id.Status)
	}
	fmt.Println()

	// Step 6: Revoke the first identity.
	//
	// RevokeIdentity sets Status to StatusRevoked. Subsequent ResolveIdentity
	// calls for this DID will return ErrIdentityRevoked.
	if err := manager.RevokeIdentity(ctx, agentIdentity.DID); err != nil {
		log.Fatalf("RevokeIdentity: %v", err)
	}
	fmt.Printf("Revoked identity: %s\n", agentIdentity.DID)

	// Confirm that resolution now fails with a revocation error.
	_, err = manager.ResolveIdentity(ctx, agentIdentity.DID)
	if err != nil {
		fmt.Printf("ResolveIdentity after revoke — expected error: %v\n", err)
	}
}

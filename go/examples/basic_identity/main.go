// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

// basic_identity demonstrates creating an agent identity, issuing a
// Verifiable Credential, and verifying it — all without any network calls.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aumos-ai/agent-identity-framework/identity"
	"github.com/aumos-ai/agent-identity-framework/keys"
)

func main() {
	ctx := context.Background()

	// --- 1. Build an IdentityManager backed by in-memory stores ---

	keyStore := keys.NewInMemoryKeyStore()
	mgr, err := identity.NewIdentityManager(identity.ManagerOptions{
		Store:      identity.NewInMemoryStore(),
		KeyManager: keyStore,
		DefaultTTL: 72 * time.Hour,
	})
	if err != nil {
		log.Fatalf("NewIdentityManager: %v", err)
	}

	// --- 2. Create an agent identity (did:key method) ---

	ownerDID := "did:web:example.com:owners:org-1"
	agent, err := mgr.CreateIdentity(ctx, identity.CreateOptions{
		OwnerDID: ownerDID,
		TTL:      24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("CreateIdentity: %v", err)
	}

	fmt.Println("=== Agent Identity Created ===")
	fmt.Printf("DID:        %s\n", agent.DID)
	fmt.Printf("OwnerDID:   %s\n", agent.OwnerDID)
	fmt.Printf("Status:     %s\n", agent.Status)
	fmt.Printf("CreatedAt:  %s\n", agent.CreatedAt.Format(time.RFC3339))
	fmt.Printf("ExpiresAt:  %s\n", agent.ExpiresAt.Format(time.RFC3339))
	fmt.Println()

	// --- 3. Issue a Verifiable Credential ---

	issuer := identity.NewCredentialIssuer(keyStore)
	vc, err := issuer.Issue(ctx, identity.IssueOptions{
		IssuerDID:      ownerDID,
		SubjectID:      agent.DID,
		CredentialType: "AgentOperationalCredential",
		Claims: map[string]interface{}{
			"agentDID":    agent.DID,
			"issuedTo":    "production-fleet",
			"permissions": []string{"read", "write"},
		},
		TTL:          12 * time.Hour,
		SigningKeyID: agent.ActiveKeyID,
	})
	if err != nil {
		log.Fatalf("Issue credential: %v", err)
	}

	fmt.Println("=== Verifiable Credential Issued ===")
	vcJSON, _ := json.MarshalIndent(vc, "", "  ")
	fmt.Println(string(vcJSON))
	fmt.Println()

	// --- 4. Resolve the DID document locally (did:key requires no network) ---

	resolver := identity.NewDIDResolver(identity.ResolverOptions{})
	doc, err := resolver.Resolve(ctx, agent.DID)
	if err != nil {
		log.Fatalf("Resolve DID: %v", err)
	}
	fmt.Println("=== DID Document Resolved ===")
	docJSON, _ := json.MarshalIndent(doc, "", "  ")
	fmt.Println(string(docJSON))
	fmt.Println()

	// --- 5. Verify the credential using the resolved DID document ---

	verifier := identity.NewCredentialVerifier(resolver)

	// Temporarily fix the issuerDID to agent.DID so it can be resolved locally.
	// In practice the issuer is the ownerDID resolved via did:web.
	vc.Issuer = agent.DID
	vc.Proof.VerificationMethod = agent.DID + "#key-1"

	result, err := verifier.VerifyCredential(ctx, vc)
	if err != nil {
		log.Fatalf("VerifyCredential: %v", err)
	}

	fmt.Println("=== Verification Result ===")
	fmt.Printf("Valid:        %v\n", result.Valid)
	fmt.Printf("IssuerDID:   %s\n", result.IssuerDID)
	fmt.Printf("SubjectID:   %s\n", result.SubjectID)
	if !result.Valid {
		fmt.Printf("Reason:      %s\n", result.Reason)
		os.Exit(1)
	}

	fmt.Println("\nDone.")
}

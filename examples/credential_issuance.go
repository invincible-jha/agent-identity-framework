// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

// credential_issuance demonstrates issuing and verifying W3C Verifiable Credentials
// for AI agents using the agent-identity-framework. It shows how to:
//   - Issue a Verifiable Credential signed with the agent's Ed25519 key
//   - Inspect the credential structure (context, type, issuer, subject, proof)
//   - Verify the credential's Ed25519 proof using the issuer's DID Document
//   - Check whether the credential has expired
//   - Handle a tampered credential (invalid proof)
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aumos-ai/agent-identity-framework/identity"
	"github.com/aumos-ai/agent-identity-framework/keys"
	"github.com/aumos-ai/agent-identity-framework/types"
)

func main() {
	ctx := context.Background()

	// Step 1: Create an issuer agent identity.
	//
	// The issuer's private key is stored in the InMemoryKeyStore and is used
	// to sign credentials. The issuer's DID is embedded in the credential's
	// issuer field so verifiers can resolve the key for verification.
	store := identity.NewInMemoryStore()
	keyStore := keys.NewInMemoryKeyStore()

	manager, err := identity.NewIdentityManager(identity.ManagerOptions{
		Store:      store,
		KeyManager: keyStore,
		DefaultTTL: 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("NewIdentityManager: %v", err)
	}

	issuerIdentity, err := manager.CreateIdentity(ctx, identity.CreateOptions{
		OwnerDID:  "did:web:issuer.example:org",
		DIDMethod: types.DIDMethodKey,
	})
	if err != nil {
		log.Fatalf("CreateIdentity (issuer): %v", err)
	}
	fmt.Printf("Issuer DID: %s\n\n", issuerIdentity.DID)

	// Step 2: Create a subject agent identity.
	//
	// The subject is the agent the credential is about. Its DID appears in
	// the credentialSubject.id field.
	subjectIdentity, err := manager.CreateIdentity(ctx, identity.CreateOptions{
		OwnerDID:  "did:web:issuer.example:org",
		DIDMethod: types.DIDMethodKey,
	})
	if err != nil {
		log.Fatalf("CreateIdentity (subject): %v", err)
	}
	fmt.Printf("Subject DID: %s\n\n", subjectIdentity.DID)

	// Step 3: Issue a Verifiable Credential.
	//
	// The CredentialIssuer creates a W3C-compliant VC, signs the canonical
	// (proof-free) JSON representation with the issuer's Ed25519 key, and
	// attaches a Linked Data Proof to the credential.
	issuer := identity.NewCredentialIssuer(keyStore)

	credential, err := issuer.Issue(ctx, identity.IssueOptions{
		IssuerDID:      issuerIdentity.DID,
		SubjectID:      subjectIdentity.DID,
		CredentialType: "AgentCapabilityCredential",
		Claims: map[string]interface{}{
			"allowedActions": []string{"file:read", "memory:read"},
			"trustLevel":     3,
			"scope":          "project-alpha",
		},
		TTL:          6 * time.Hour,
		SigningKeyID: issuerIdentity.ActiveKeyID,
	})
	if err != nil {
		log.Fatalf("Issue: %v", err)
	}

	fmt.Printf("Issued Verifiable Credential\n")
	fmt.Printf("  ID:           %s\n", credential.ID)
	fmt.Printf("  Type:         %v\n", credential.Type)
	fmt.Printf("  Issuer:       %s\n", credential.Issuer)
	fmt.Printf("  IssuanceDate: %s\n", credential.IssuanceDate)
	fmt.Printf("  Expiration:   %s\n", credential.ExpirationDate)
	fmt.Printf("  Subject ID:   %s\n", credential.CredentialSubject["id"])
	fmt.Printf("  Claims:       %v\n", credential.CredentialSubject["allowedActions"])
	fmt.Println()

	if credential.Proof != nil {
		fmt.Printf("Credential Proof\n")
		fmt.Printf("  Type:               %s\n", credential.Proof.Type)
		fmt.Printf("  VerificationMethod: %s\n", credential.Proof.VerificationMethod)
		fmt.Printf("  ProofPurpose:       %s\n", credential.Proof.ProofPurpose)
		fmt.Printf("  ProofValue length:  %d chars\n\n", len(credential.Proof.ProofValue))
	}

	// Step 4: Verify the credential.
	//
	// CredentialVerifier resolves the issuer's DID Document to obtain the
	// public key, then verifies the Ed25519 signature over the canonical
	// credential bytes. For did:key the resolution is purely local.
	resolver := identity.NewDIDResolver(identity.ResolverOptions{})
	verifier := identity.NewCredentialVerifier(resolver)

	result, err := verifier.VerifyCredential(ctx, credential)
	if err != nil {
		log.Fatalf("VerifyCredential: %v", err)
	}

	fmt.Printf("Verification Result\n")
	fmt.Printf("  Valid:        %v\n", result.Valid)
	fmt.Printf("  IssuerDID:    %s\n", result.IssuerDID)
	fmt.Printf("  SubjectID:    %s\n", result.SubjectID)
	fmt.Printf("  CredentialID: %s\n", result.CredentialID)
	if result.ExpiresAt != nil {
		fmt.Printf("  ExpiresAt:    %s\n", result.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("  Expired:      %v\n", time.Now().UTC().After(*result.ExpiresAt))
	}
	fmt.Println()

	// Step 5: Detect a tampered credential.
	//
	// Modifying any field in the credential after signing invalidates the proof.
	// The verifier catches this and returns Valid = false with a descriptive reason.
	tampered := *credential
	tampered.CredentialSubject = map[string]interface{}{
		"id":             subjectIdentity.DID,
		"allowedActions": []string{"file:write", "file:delete"}, // tampered claim
		"trustLevel":     5,                                      // escalated level
	}
	// Proof remains from the original — it no longer matches the tampered body.

	tamperedResult, err := verifier.VerifyCredential(ctx, &tampered)
	if err != nil {
		log.Fatalf("VerifyCredential (tampered): %v", err)
	}

	fmt.Printf("Tampered Credential Verification\n")
	fmt.Printf("  Valid:  %v (expected: false)\n", tamperedResult.Valid)
	fmt.Printf("  Reason: %s\n", tamperedResult.Reason)
}

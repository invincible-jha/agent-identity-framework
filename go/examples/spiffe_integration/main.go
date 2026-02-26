// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

// spiffe_integration demonstrates adapting a SPIFFE workload identity into an
// AgentIdentity and parsing a JWT SVID.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aumos-ai/agent-identity-framework/identity"
	"github.com/aumos-ai/agent-identity-framework/keys"
	"github.com/aumos-ai/agent-identity-framework/spiffe"
)

func main() {
	ctx := context.Background()

	// --- 1. Bootstrap an IdentityManager ---

	mgr, err := identity.NewIdentityManager(identity.ManagerOptions{
		Store:      identity.NewInMemoryStore(),
		KeyManager: keys.NewInMemoryKeyStore(),
		DefaultTTL: 8 * time.Hour,
	})
	if err != nil {
		log.Fatalf("NewIdentityManager: %v", err)
	}

	// --- 2. Create a WorkloadIdentityAdapter ---

	adapter, err := spiffe.NewWorkloadIdentityAdapter(spiffe.WorkloadIdentityAdapterOptions{
		Manager:         mgr,
		DefaultOwnerDID: "did:web:example.com:operators:platform-team",
		DefaultTTL:      8 * time.Hour,
	})
	if err != nil {
		log.Fatalf("NewWorkloadIdentityAdapter: %v", err)
	}

	// --- 3. Adapt a SPIFFE workload identity ---

	spiffeID := "spiffe://example.com/ns/production/sa/inference-agent"
	workload, err := adapter.AdaptWorkload(ctx, spiffeID, "")
	if err != nil {
		log.Fatalf("AdaptWorkload: %v", err)
	}

	fmt.Println("=== Workload Identity Adapted ===")
	fmt.Printf("SPIFFE ID:    %s\n", workload.SPIFFEID)
	fmt.Printf("Trust Domain: %s\n", workload.TrustDomain)
	fmt.Printf("Path:         %s\n", workload.WorkloadPath)
	fmt.Printf("Agent DID:    %s\n", workload.AgentIdentity.DID)
	fmt.Printf("Agent Status: %s\n", workload.AgentIdentity.Status)
	fmt.Println()

	// --- 4. Parse a SPIFFE ID ---

	trustDomain, path, err := spiffe.ParseSPIFFEID(spiffeID)
	if err != nil {
		log.Fatalf("ParseSPIFFEID: %v", err)
	}
	fmt.Println("=== Parsed SPIFFE ID ===")
	fmt.Printf("Trust Domain: %s\n", trustDomain)
	fmt.Printf("Path:         %s\n", path)
	fmt.Println()

	// --- 5. Demonstrate SVIDHandler with a synthetic JWT SVID ---

	handler := spiffe.NewSVIDHandler()

	// A real JWT would be obtained from the SPIFFE workload API.
	// Here we demonstrate that a well-formed JWT with a valid SPIFFE sub is parsed.
	// The token below is NOT cryptographically signed — it is for structural demo only.
	syntheticJWT := buildUnsignedDemoJWT("spiffe://example.com/ns/production/sa/inference-agent")
	jwtSVID, err := handler.ParseJWTSVID(syntheticJWT)
	if err != nil {
		// Expected if the demo token is expired; print and continue.
		fmt.Printf("ParseJWTSVID (demo token): %v\n", err)
	} else {
		fmt.Println("=== JWT SVID Parsed ===")
		fmt.Printf("SPIFFE ID:  %s\n", jwtSVID.SPIFFEID)
		fmt.Printf("Audience:   %v\n", jwtSVID.Audience)
		fmt.Printf("SVID Type:  %s\n", jwtSVID.SVIDType)
	}
}

// buildUnsignedDemoJWT creates a structurally valid (but unsigned) JWT for demo purposes.
// The payload encodes a SPIFFE sub with a far-future exp.
func buildUnsignedDemoJWT(spiffeID string) string {
	import_base64 := func(s string) string {
		// simple passthrough — we build raw base64url segments
		return s
	}
	_ = import_base64

	// header: {"alg":"EdDSA","typ":"JWT"}
	header := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9"
	// payload: {"sub":"<spiffeID>","aud":["demo"],"iat":1700000000,"exp":9999999999}
	// Pre-encoded for this fixed demo value:
	_ = spiffeID
	payload := "eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbS9ucy9wcm9kdWN0aW9uL3NhL2luZmVyZW5jZS1hZ2VudCIsImF1ZCI6WyJkZW1vIl0sImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo5OTk5OTk5OTk5fQ"
	signature := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	return header + "." + payload + "." + signature
}

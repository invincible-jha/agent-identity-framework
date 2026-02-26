// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

// Package spiffe provides adapters between SPIFFE workload identity and the
// agent-identity-framework's AgentIdentity model.
//
// SPIFFE (Secure Production Identity Framework for Everyone) assigns workload
// identities via SPIFFE IDs of the form spiffe://<trust-domain>/<path>.
// This package does NOT integrate with the Trust Ladder and has no concept of
// trust levels.
package spiffe

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aumos-ai/agent-identity-framework/identity"
	"github.com/aumos-ai/agent-identity-framework/types"
)

// WorkloadIdentity represents a SPIFFE workload identity that has been
// adapted for use with the agent-identity-framework.
type WorkloadIdentity struct {
	// SPIFFEID is the canonical SPIFFE ID for this workload (e.g. "spiffe://example.com/agents/agent-1").
	SPIFFEID string
	// AgentIdentity is the corresponding agent-identity-framework identity.
	// It is nil if no mapping has been created yet.
	AgentIdentity *identity.AgentIdentity
	// TrustDomain is extracted from the SPIFFE ID (e.g. "example.com").
	TrustDomain string
	// WorkloadPath is the path segment of the SPIFFE ID (e.g. "/agents/agent-1").
	WorkloadPath string
}

// WorkloadIdentityAdapterOptions configures a WorkloadIdentityAdapter.
type WorkloadIdentityAdapterOptions struct {
	// Manager is used to create and resolve AgentIdentity records.
	Manager *identity.IdentityManager
	// DefaultOwnerDID is used when no explicit OwnerDID is provided.
	DefaultOwnerDID string
	// DefaultTTL is the identity TTL when not overridden per-call. Defaults to 24h.
	DefaultTTL time.Duration
}

// WorkloadIdentityAdapter maps SPIFFE workload identities to AgentIdentity records.
// It does not interact with any SPIFFE workload API (spiffe.io/go-spiffe);
// it receives SPIFFE IDs as strings and adapts them into the agent identity model.
type WorkloadIdentityAdapter struct {
	manager         *identity.IdentityManager
	defaultOwnerDID string
	defaultTTL      time.Duration
}

// NewWorkloadIdentityAdapter constructs a WorkloadIdentityAdapter.
func NewWorkloadIdentityAdapter(opts WorkloadIdentityAdapterOptions) (*WorkloadIdentityAdapter, error) {
	if opts.Manager == nil {
		return nil, fmt.Errorf("spiffe: WorkloadIdentityAdapterOptions.Manager must not be nil")
	}
	ttl := opts.DefaultTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &WorkloadIdentityAdapter{
		manager:         opts.Manager,
		defaultOwnerDID: opts.DefaultOwnerDID,
		defaultTTL:      ttl,
	}, nil
}

// ParseSPIFFEID parses and validates a SPIFFE ID string.
// A valid SPIFFE ID has the form spiffe://<trust-domain>/<path>.
func ParseSPIFFEID(spiffeID string) (trustDomain, path string, err error) {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return "", "", fmt.Errorf("spiffe: parse SPIFFE ID %q: %w", spiffeID, err)
	}
	if u.Scheme != "spiffe" {
		return "", "", fmt.Errorf("spiffe: invalid scheme %q in SPIFFE ID %q (must be 'spiffe')", u.Scheme, spiffeID)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("spiffe: missing trust domain in SPIFFE ID %q", spiffeID)
	}
	if u.Path == "" || u.Path == "/" {
		return "", "", fmt.Errorf("spiffe: SPIFFE ID %q must include a path", spiffeID)
	}
	return u.Host, u.Path, nil
}

// AdaptWorkload creates (or retrieves) an AgentIdentity for the given SPIFFE ID.
// The DID is derived as did:web:<trust-domain>:<encoded-path>.
//
// If ownerDID is empty, the adapter's DefaultOwnerDID is used.
func (a *WorkloadIdentityAdapter) AdaptWorkload(ctx context.Context, spiffeID, ownerDID string) (*WorkloadIdentity, error) {
	trustDomain, path, err := ParseSPIFFEID(spiffeID)
	if err != nil {
		return nil, err
	}

	owner := ownerDID
	if owner == "" {
		owner = a.defaultOwnerDID
	}
	if owner == "" {
		return nil, fmt.Errorf("spiffe: ownerDID must be provided when DefaultOwnerDID is not set")
	}

	// Encode path segments as colon-separated (did:web convention).
	webPath := strings.Trim(path, "/")
	webPath = strings.ReplaceAll(webPath, "/", ":")

	agent, err := a.manager.CreateIdentity(ctx, identity.CreateOptions{
		OwnerDID:  owner,
		TTL:       a.defaultTTL,
		DIDMethod: types.DIDMethodWeb,
		WebHost:   trustDomain,
		WebPath:   webPath,
	})
	if err != nil {
		return nil, fmt.Errorf("spiffe: create identity for workload %s: %w", spiffeID, err)
	}

	return &WorkloadIdentity{
		SPIFFEID:      spiffeID,
		AgentIdentity: agent,
		TrustDomain:   trustDomain,
		WorkloadPath:  path,
	}, nil
}

// ResolveWorkload looks up a previously adapted workload by its SPIFFE ID,
// converting it back to the DID and resolving the identity.
func (a *WorkloadIdentityAdapter) ResolveWorkload(ctx context.Context, spiffeID string) (*WorkloadIdentity, error) {
	trustDomain, path, err := ParseSPIFFEID(spiffeID)
	if err != nil {
		return nil, err
	}

	webPath := strings.Trim(path, "/")
	webPath = strings.ReplaceAll(webPath, "/", ":")

	// The DID was derived deterministically in AdaptWorkload — we can derive it
	// again to look it up. However, CreateIdentity appends a UUID, so the DID
	// is not deterministic from the SPIFFE ID alone. In a production deployment,
	// callers would store the SPIFFE-ID -> DID mapping. Here we surface the limitation.
	return nil, fmt.Errorf("spiffe: ResolveWorkload requires a persistent SPIFFE-ID->DID index; trust-domain=%s path=%s", trustDomain, webPath)
}

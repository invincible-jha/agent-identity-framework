// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

// Package identity is the primary package for agent identity management.
// It provides AgentIdentity (the core data type), IdentityManager (the main
// service object), and an in-memory IdentityStore.
package identity

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/aumos-ai/agent-identity-framework/keys"
	"github.com/aumos-ai/agent-identity-framework/types"
)

// AgentIdentity is the canonical representation of a verified AI agent identity.
type AgentIdentity struct {
	// DID is the Decentralized Identifier for this agent (did:key or did:web).
	DID string `json:"did"`
	// OwnerDID identifies the person or organization that created this agent identity.
	OwnerDID string `json:"ownerDid"`
	// PublicKey is the agent's Ed25519 public key.
	PublicKey ed25519.PublicKey `json:"publicKey"`
	// ActiveKeyID is the KeyManager key ID corresponding to PublicKey.
	ActiveKeyID string `json:"activeKeyId"`
	// CreatedAt is the UTC timestamp when this identity was created.
	CreatedAt time.Time `json:"createdAt"`
	// ExpiresAt is the UTC timestamp after which this identity is no longer valid.
	ExpiresAt time.Time `json:"expiresAt"`
	// Status is the current lifecycle state of this identity.
	Status types.IdentityStatus `json:"status"`
}

// IsValid reports whether the identity is active and not expired.
func (a *AgentIdentity) IsValid() bool {
	if a.Status != types.StatusActive {
		return false
	}
	return time.Now().UTC().Before(a.ExpiresAt)
}

// IdentityStore is the interface for persisting and retrieving AgentIdentity records.
type IdentityStore interface {
	Put(ctx context.Context, identity *AgentIdentity) error
	Get(ctx context.Context, did string) (*AgentIdentity, error)
	List(ctx context.Context) ([]*AgentIdentity, error)
	Delete(ctx context.Context, did string) error
}

// InMemoryStore is a thread-safe, in-process IdentityStore. Suitable for tests
// and short-lived deployments.
type InMemoryStore struct {
	mu         sync.RWMutex
	identities map[string]*AgentIdentity
}

// NewInMemoryStore returns an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{identities: make(map[string]*AgentIdentity)}
}

func (s *InMemoryStore) Put(_ context.Context, identity *AgentIdentity) error {
	if identity == nil {
		return fmt.Errorf("identity store: cannot store nil AgentIdentity")
	}
	s.mu.Lock()
	s.identities[identity.DID] = identity
	s.mu.Unlock()
	return nil
}

func (s *InMemoryStore) Get(_ context.Context, did string) (*AgentIdentity, error) {
	s.mu.RLock()
	id, ok := s.identities[did]
	s.mu.RUnlock()
	if !ok {
		return nil, &types.ErrIdentityNotFound{DID: did}
	}
	return id, nil
}

func (s *InMemoryStore) List(_ context.Context) ([]*AgentIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*AgentIdentity, 0, len(s.identities))
	for _, id := range s.identities {
		out = append(out, id)
	}
	return out, nil
}

func (s *InMemoryStore) Delete(_ context.Context, did string) error {
	s.mu.Lock()
	delete(s.identities, did)
	s.mu.Unlock()
	return nil
}

// CreateOptions carries parameters for IdentityManager.CreateIdentity.
type CreateOptions struct {
	// OwnerDID is the DID of the entity creating this agent identity. Required.
	OwnerDID string
	// TTL is how long the identity remains valid. Defaults to 24 hours.
	TTL time.Duration
	// DIDMethod controls whether the resulting DID is did:key or did:web.
	// Defaults to did:key.
	DIDMethod types.DIDMethod
	// WebHost is required when DIDMethod is did:web (e.g. "example.com").
	WebHost string
	// WebPath is an optional path suffix for did:web identities.
	WebPath string
}

// ManagerOptions configures an IdentityManager.
type ManagerOptions struct {
	// Store is used to persist AgentIdentity records. Required.
	Store IdentityStore
	// KeyManager is used to generate and store key pairs. If nil, an
	// InMemoryKeyStore is used.
	KeyManager keys.KeyManager
	// DefaultTTL is used when CreateOptions.TTL is zero. Defaults to 24h.
	DefaultTTL time.Duration
}

// IdentityManager is the primary service object. All exported methods are safe
// for concurrent use from multiple goroutines.
type IdentityManager struct {
	store      IdentityStore
	keyManager keys.KeyManager
	defaultTTL time.Duration
}

// NewIdentityManager constructs an IdentityManager from the provided options.
func NewIdentityManager(opts ManagerOptions) (*IdentityManager, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("identity: ManagerOptions.Store must not be nil")
	}
	km := opts.KeyManager
	if km == nil {
		km = keys.NewInMemoryKeyStore()
	}
	ttl := opts.DefaultTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &IdentityManager{
		store:      opts.Store,
		keyManager: km,
		defaultTTL: ttl,
	}, nil
}

// CreateIdentity generates a new Ed25519 key pair, derives a DID, creates an
// AgentIdentity record, persists it, and returns it.
func (m *IdentityManager) CreateIdentity(ctx context.Context, opts CreateOptions) (*AgentIdentity, error) {
	if opts.OwnerDID == "" {
		return nil, fmt.Errorf("identity: CreateOptions.OwnerDID must not be empty")
	}

	kp, err := m.keyManager.Generate(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity: generate key pair: %w", err)
	}

	method := opts.DIDMethod
	if method == "" {
		method = types.DIDMethodKey
	}

	var did string
	switch method {
	case types.DIDMethodKey:
		did, err = DeriveKeyDID(kp.PublicKey)
	case types.DIDMethodWeb:
		if opts.WebHost == "" {
			return nil, fmt.Errorf("identity: WebHost required for did:web")
		}
		did = DeriveWebDID(opts.WebHost, opts.WebPath, uuid.NewString())
	default:
		return nil, &types.ErrUnsupportedDIDMethod{Method: string(method)}
	}
	if err != nil {
		return nil, fmt.Errorf("identity: derive DID: %w", err)
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = m.defaultTTL
	}

	now := time.Now().UTC()
	agent := &AgentIdentity{
		DID:         did,
		OwnerDID:    opts.OwnerDID,
		PublicKey:   kp.PublicKey,
		ActiveKeyID: kp.KeyID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		Status:      types.StatusActive,
	}

	if err := m.store.Put(ctx, agent); err != nil {
		return nil, fmt.Errorf("identity: persist AgentIdentity: %w", err)
	}

	return agent, nil
}

// ResolveIdentity looks up an AgentIdentity by DID in the local store.
// For remote resolution of did:web documents, use the DIDResolver.
func (m *IdentityManager) ResolveIdentity(ctx context.Context, did string) (*AgentIdentity, error) {
	agent, err := m.store.Get(ctx, did)
	if err != nil {
		return nil, fmt.Errorf("identity: resolve %s: %w", did, err)
	}

	if agent.Status == types.StatusRevoked {
		return nil, &types.ErrIdentityRevoked{DID: did}
	}
	if !agent.ExpiresAt.IsZero() && time.Now().UTC().After(agent.ExpiresAt) {
		agent.Status = types.StatusExpired
		_ = m.store.Put(ctx, agent)
		return nil, &types.ErrIdentityExpired{DID: did}
	}

	return agent, nil
}

// RevokeIdentity marks an AgentIdentity as revoked.
func (m *IdentityManager) RevokeIdentity(ctx context.Context, did string) error {
	agent, err := m.store.Get(ctx, did)
	if err != nil {
		return fmt.Errorf("identity: revoke %s — load: %w", did, err)
	}
	agent.Status = types.StatusRevoked
	if err := m.store.Put(ctx, agent); err != nil {
		return fmt.Errorf("identity: revoke %s — persist: %w", did, err)
	}
	return nil
}

// KeyManager returns the underlying KeyManager for direct key operations.
func (m *IdentityManager) KeyManager() keys.KeyManager {
	return m.keyManager
}

// Store returns the underlying IdentityStore.
func (m *IdentityManager) Store() IdentityStore {
	return m.store
}

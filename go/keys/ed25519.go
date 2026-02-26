// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/aumos-ai/agent-identity-framework/types"
)

// InMemoryKeyStore is a thread-safe, in-process KeyManager implementation.
// Key material exists only for the lifetime of the process. Suitable for
// short-lived agents and integration tests.
type InMemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*KeyPair
}

// NewInMemoryKeyStore constructs an empty InMemoryKeyStore.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{
		keys: make(map[string]*KeyPair),
	}
}

// Generate creates a fresh Ed25519 key pair, stores it, and returns it.
func (s *InMemoryKeyStore) Generate(ctx context.Context) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keys: generate Ed25519 key: %w", err)
	}

	kp := &KeyPair{
		KeyID:      uuid.NewString(),
		Algorithm:  types.KeyAlgorithmEd25519,
		PublicKey:  pub,
		PrivateKey: priv,
	}

	s.mu.Lock()
	s.keys[kp.KeyID] = kp
	s.mu.Unlock()

	return kp, nil
}

// Store saves an externally provided key pair.
func (s *InMemoryKeyStore) Store(_ context.Context, kp *KeyPair) error {
	if kp == nil {
		return fmt.Errorf("keys: cannot store nil KeyPair")
	}
	if kp.KeyID == "" {
		return fmt.Errorf("keys: KeyPair.KeyID must not be empty")
	}

	s.mu.Lock()
	s.keys[kp.KeyID] = kp
	s.mu.Unlock()
	return nil
}

// Load retrieves a key pair by ID.
func (s *InMemoryKeyStore) Load(_ context.Context, keyID string) (*KeyPair, error) {
	s.mu.RLock()
	kp, ok := s.keys[keyID]
	s.mu.RUnlock()

	if !ok {
		return nil, &types.ErrKeyNotFound{KeyID: keyID}
	}
	return kp, nil
}

// Rotate generates a new key pair to replace oldKeyID.
// The old key pair is retained in the store.
func (s *InMemoryKeyStore) Rotate(ctx context.Context, oldKeyID string, reason types.KeyRotationReason) (*KeyPair, *types.KeyRotationRecord, error) {
	s.mu.RLock()
	_, ok := s.keys[oldKeyID]
	s.mu.RUnlock()

	if !ok {
		return nil, nil, &types.ErrKeyNotFound{KeyID: oldKeyID}
	}

	newKP, err := s.Generate(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: rotate — generate replacement key: %w", err)
	}

	record := &types.KeyRotationRecord{
		PreviousKeyID: oldKeyID,
		NewKeyID:      newKP.KeyID,
		Reason:        reason,
		RotatedAt:     time.Now().UTC(),
	}

	return newKP, record, nil
}

// List returns all key IDs currently held in the store.
func (s *InMemoryKeyStore) List(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, id)
	}
	return ids, nil
}

// Sign produces an Ed25519 signature over message using the key identified by keyID.
func (s *InMemoryKeyStore) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	kp, err := s.Load(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("keys: sign — load key: %w", err)
	}
	if kp.PrivateKey == nil {
		return nil, fmt.Errorf("keys: sign — private key not available for %s", keyID)
	}
	return ed25519.Sign(kp.PrivateKey, message), nil
}

// Verify returns nil if the Ed25519 signature over message is valid for the given public key.
func Verify(publicKey ed25519.PublicKey, message, signature []byte) error {
	if !ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("keys: Ed25519 signature verification failed")
	}
	return nil
}

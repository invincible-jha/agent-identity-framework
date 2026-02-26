// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

package keys

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aumos-ai/agent-identity-framework/types"
)

// RotationPolicy defines when automatic key rotation should occur.
type RotationPolicy struct {
	// MaxAge is the maximum lifetime of a key before it is rotated.
	MaxAge time.Duration
	// Reason is recorded in the rotation record when automatic rotation fires.
	Reason types.KeyRotationReason
}

// DefaultRotationPolicy returns a policy that rotates keys every 90 days.
func DefaultRotationPolicy() RotationPolicy {
	return RotationPolicy{
		MaxAge: 90 * 24 * time.Hour,
		Reason: types.KeyRotationReasonScheduled,
	}
}

// KeyRotator coordinates identity-continuity-preserving key rotation.
// It maintains the mapping from an agent DID to its current active key ID,
// and delegates key material operations to an underlying KeyManager.
type KeyRotator struct {
	manager  KeyManager
	policy   RotationPolicy
	mu       sync.Mutex
	// activeKeyByDID maps each agent DID to its current active key ID.
	activeKeyByDID map[string]string
	// rotationHistory records all past rotations per agent DID.
	rotationHistory map[string][]*types.KeyRotationRecord
}

// NewKeyRotator constructs a KeyRotator that uses the provided KeyManager and policy.
func NewKeyRotator(manager KeyManager, policy RotationPolicy) *KeyRotator {
	return &KeyRotator{
		manager:         manager,
		policy:          policy,
		activeKeyByDID:  make(map[string]string),
		rotationHistory: make(map[string][]*types.KeyRotationRecord),
	}
}

// RegisterDID associates agentDID with an existing key identified by keyID.
// Call this after CreateIdentity so the rotator can track the key.
func (r *KeyRotator) RegisterDID(agentDID, keyID string) {
	r.mu.Lock()
	r.activeKeyByDID[agentDID] = keyID
	r.mu.Unlock()
}

// ActiveKeyID returns the current active key ID for agentDID.
func (r *KeyRotator) ActiveKeyID(agentDID string) (string, bool) {
	r.mu.Lock()
	id, ok := r.activeKeyByDID[agentDID]
	r.mu.Unlock()
	return id, ok
}

// RotateForDID performs a key rotation for the given agent DID.
// The new key pair is returned; the old key remains accessible in the KeyManager.
// Identity continuity is preserved because the DID itself does not change.
func (r *KeyRotator) RotateForDID(ctx context.Context, agentDID string, reason types.KeyRotationReason) (*KeyPair, *types.KeyRotationRecord, error) {
	r.mu.Lock()
	oldKeyID, ok := r.activeKeyByDID[agentDID]
	r.mu.Unlock()

	if !ok {
		return nil, nil, fmt.Errorf("keys: rotate — no active key registered for DID %s", agentDID)
	}

	newKP, record, err := r.manager.Rotate(ctx, oldKeyID, reason)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: rotate — KeyManager.Rotate: %w", err)
	}

	r.mu.Lock()
	r.activeKeyByDID[agentDID] = newKP.KeyID
	r.rotationHistory[agentDID] = append(r.rotationHistory[agentDID], record)
	r.mu.Unlock()

	return newKP, record, nil
}

// RotationHistory returns all recorded rotation events for agentDID.
func (r *KeyRotator) RotationHistory(agentDID string) []*types.KeyRotationRecord {
	r.mu.Lock()
	defer r.mu.Unlock()

	history := r.rotationHistory[agentDID]
	if len(history) == 0 {
		return nil
	}
	// Return a copy so callers cannot mutate internal state.
	out := make([]*types.KeyRotationRecord, len(history))
	copy(out, history)
	return out
}

// CheckAndRotate examines the key's creation time (approximated by the first rotation
// record or a provided createdAt) and rotates if MaxAge has elapsed.
// Returns (newKP, record, nil) if a rotation occurred, or (nil, nil, nil) if not needed.
func (r *KeyRotator) CheckAndRotate(ctx context.Context, agentDID string, keyCreatedAt time.Time) (*KeyPair, *types.KeyRotationRecord, error) {
	if time.Since(keyCreatedAt) < r.policy.MaxAge {
		return nil, nil, nil
	}
	return r.RotateForDID(ctx, agentDID, r.policy.Reason)
}

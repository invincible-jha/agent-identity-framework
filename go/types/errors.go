// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

package types

import "fmt"

// ErrIdentityNotFound is returned when a DID cannot be resolved in the local store.
type ErrIdentityNotFound struct {
	DID string
}

func (e *ErrIdentityNotFound) Error() string {
	return fmt.Sprintf("identity not found: %s", e.DID)
}

// ErrIdentityExpired is returned when an identity's ExpiresAt is in the past.
type ErrIdentityExpired struct {
	DID string
}

func (e *ErrIdentityExpired) Error() string {
	return fmt.Sprintf("identity expired: %s", e.DID)
}

// ErrIdentityRevoked is returned when an identity has been explicitly revoked.
type ErrIdentityRevoked struct {
	DID string
}

func (e *ErrIdentityRevoked) Error() string {
	return fmt.Sprintf("identity revoked: %s", e.DID)
}

// ErrUnsupportedDIDMethod is returned when a DID uses a method this package does not implement.
type ErrUnsupportedDIDMethod struct {
	Method string
}

func (e *ErrUnsupportedDIDMethod) Error() string {
	return fmt.Sprintf("unsupported DID method: %s", e.Method)
}

// ErrInvalidDID is returned when a DID string is malformed.
type ErrInvalidDID struct {
	DID    string
	Reason string
}

func (e *ErrInvalidDID) Error() string {
	return fmt.Sprintf("invalid DID %q: %s", e.DID, e.Reason)
}

// ErrKeyNotFound is returned when a key ID cannot be located in the key store.
type ErrKeyNotFound struct {
	KeyID string
}

func (e *ErrKeyNotFound) Error() string {
	return fmt.Sprintf("key not found: %s", e.KeyID)
}

// ErrVerificationFailed is returned when a credential's proof does not verify.
type ErrVerificationFailed struct {
	Reason string
}

func (e *ErrVerificationFailed) Error() string {
	return fmt.Sprintf("credential verification failed: %s", e.Reason)
}

// ErrDIDResolutionFailed is returned when a did:web document cannot be fetched or parsed.
type ErrDIDResolutionFailed struct {
	DID    string
	Reason string
}

func (e *ErrDIDResolutionFailed) Error() string {
	return fmt.Sprintf("DID resolution failed for %s: %s", e.DID, e.Reason)
}

// ErrSVIDInvalid is returned when an SVID cannot be parsed or its signature is invalid.
type ErrSVIDInvalid struct {
	Reason string
}

func (e *ErrSVIDInvalid) Error() string {
	return fmt.Sprintf("invalid SVID: %s", e.Reason)
}

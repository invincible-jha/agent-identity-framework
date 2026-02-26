# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""Shared value types for the aumos-agent-identity Python SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class DIDMethod(str, Enum):
    """Supported DID methods. Only did:web and did:key are implemented."""

    WEB = "web"
    KEY = "key"


class IdentityStatus(str, Enum):
    """Lifecycle status of an agent identity."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class KeyAlgorithm(str, Enum):
    """Cryptographic algorithm used by a key pair."""

    ED25519 = "Ed25519"


class ProofType(str, Enum):
    """Linked Data Proof type."""

    ED25519_SIGNATURE_2020 = "Ed25519Signature2020"


class VerificationMethodType(str, Enum):
    """Type of a DID verification method."""

    ED25519_2020 = "Ed25519VerificationKey2020"


@dataclass(frozen=True)
class VerificationMethod:
    """A single verification method entry in a DID Document."""

    id: str
    type: VerificationMethodType
    controller: str
    public_key_multibase: str


@dataclass(frozen=True)
class DIDDocument:
    """W3C DID Document."""

    context: list[str]
    id: str
    verification_method: list[VerificationMethod]
    authentication: list[str]
    assertion_method: list[str]
    created: str | None = None
    updated: str | None = None


@dataclass(frozen=True)
class CredentialProof:
    """Linked Data Proof attached to a Verifiable Credential."""

    type: ProofType
    created: str
    verification_method: str
    proof_purpose: str
    # Base64url-encoded Ed25519 signature.
    proof_value: str


@dataclass(frozen=True)
class VerifiableCredential:
    """W3C Verifiable Credential (generic schema only)."""

    context: list[str]
    id: str
    type: list[str]
    issuer: str
    issuance_date: str
    credential_subject: dict[str, Any]
    expiration_date: str | None = None
    proof: CredentialProof | None = None


@dataclass(frozen=True)
class AgentIdentity:
    """Canonical representation of a verified AI agent identity."""

    did: str
    owner_did: str
    # Base64url-encoded Ed25519 public key bytes.
    public_key_base64: str
    created_at: str
    expires_at: str
    status: IdentityStatus


@dataclass(frozen=True)
class VerificationResult:
    """Result returned by verify_credential."""

    valid: bool
    issuer_did: str
    credential_id: str
    subject_id: str | None = None
    expires_at: datetime | None = None
    # Populated when valid is False.
    reason: str | None = None


class IdentityClientError(Exception):
    """Raised when the identity server returns a non-2xx response."""

    def __init__(self, status_code: int, endpoint: str, message: str) -> None:
        self.status_code = status_code
        self.endpoint = endpoint
        super().__init__(
            f"IdentityClient [{status_code}] {endpoint}: {message}"
        )


class DIDResolutionError(Exception):
    """Raised when a DID cannot be resolved."""


class VerificationError(Exception):
    """Raised when a credential proof cannot be verified due to a structural error."""


class UnsupportedDIDMethodError(Exception):
    """Raised when a DID method is not supported."""

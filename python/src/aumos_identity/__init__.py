# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""aumos-agent-identity — SPIFFE/DID-compatible identity client for AI agents.

Quickstart
----------
>>> import asyncio
>>> from aumos_identity import IdentityClient
>>> client = IdentityClient(base_url="https://identity.example.com")
>>> identity = asyncio.run(client.resolve_identity("did:key:z..."))
>>> print(identity.status)
IdentityStatus.ACTIVE

For offline credential verification without a server:

>>> from aumos_identity import VerifiableCredential
>>> from aumos_identity.verification import verify_credential_signature
>>> result = asyncio.run(verify_credential_signature(vc))
>>> print(result.valid)
True
"""

from .client import IdentityClient
from .credential import CredentialIssuer, VerifiableCredential
from .types import (
    AgentIdentity,
    DIDDocument,
    DIDResolutionError,
    IdentityClientError,
    UnsupportedDIDMethodError,
    VerificationError,
    VerificationResult,
)
from .verification import check_expiry, verify_credential_signature

__all__ = [
    # Primary client
    "IdentityClient",
    # Core types
    "AgentIdentity",
    "DIDDocument",
    "VerifiableCredential",
    "VerificationResult",
    # Credential issuance
    "CredentialIssuer",
    # Standalone verification helpers
    "verify_credential_signature",
    "check_expiry",
    # Exceptions
    "IdentityClientError",
    "DIDResolutionError",
    "VerificationError",
    "UnsupportedDIDMethodError",
]

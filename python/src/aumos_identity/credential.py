# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""Verifiable Credential construction, canonicalization, and issuance.

This module handles the *production* side of the W3C Verifiable Credentials
Data Model — building credential documents and signing them with an Ed25519
private key.

For the *consumption* side (verification of existing credentials), see
:mod:`verification`.

Only generic W3C VC schemas are used. No AumOS-specific credential types
are defined here, in accordance with the agent-identity-framework FIRE LINE.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any

from .types import (
    CredentialProof,
    ProofType,
    VerifiableCredential,
    VerificationError,
)

# W3C VC context URLs used in all credentials produced by this module.
_VC_CONTEXT = [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
]

# The type array must always begin with "VerifiableCredential".
_BASE_TYPE = "VerifiableCredential"


class CredentialIssuer:
    """Signs and issues W3C Verifiable Credentials.

    Credentials are signed with Ed25519 using the issuer's private key.
    The proof value is a base64url-encoded Ed25519 signature over the
    canonical JSON of the credential document (serialized without its proof
    field).

    Parameters
    ----------
    issuer_did:
        The DID that will appear as the ``issuer`` field of every credential
        produced by this instance. Must be a ``did:key`` or ``did:web`` DID.
    private_key_bytes:
        Raw 32-byte Ed25519 private key seed.
    verification_method_id:
        The full verification method ID used in the proof, e.g.
        ``"did:key:z6Mk...#key-1"``.

    Examples
    --------
    >>> issuer = CredentialIssuer(
    ...     issuer_did="did:key:z6Mk...",
    ...     private_key_bytes=seed_bytes,
    ...     verification_method_id="did:key:z6Mk...#key-1",
    ... )
    >>> vc = issuer.issue(
    ...     credential_id="urn:uuid:...",
    ...     subject={"id": "did:key:z6Mk...", "role": "worker"},
    ...     additional_types=["AgentCapabilityCredential"],
    ... )
    """

    def __init__(
        self,
        *,
        issuer_did: str,
        private_key_bytes: bytes,
        verification_method_id: str,
    ) -> None:
        if len(private_key_bytes) not in (32, 64):
            raise ValueError(
                "CredentialIssuer: private_key_bytes must be a 32-byte Ed25519 seed "
                f"or a 64-byte expanded private key; got {len(private_key_bytes)} bytes"
            )
        self._issuer_did = issuer_did
        self._private_key_bytes = private_key_bytes
        self._verification_method_id = verification_method_id

    @property
    def issuer_did(self) -> str:
        """The DID used as the ``issuer`` field on all issued credentials."""
        return self._issuer_did

    def issue(
        self,
        *,
        credential_id: str,
        subject: dict[str, Any],
        additional_types: list[str] | None = None,
        issuance_date: datetime | None = None,
        expiration_date: datetime | None = None,
    ) -> VerifiableCredential:
        """Build and sign a Verifiable Credential.

        The credential is signed immediately — the returned object carries a
        populated :attr:`~types.VerifiableCredential.proof`.

        Parameters
        ----------
        credential_id:
            Globally unique URI for this credential. Use ``"urn:uuid:<uuid>"``
            when no canonical URL exists.
        subject:
            The ``credentialSubject`` dict. Should include at minimum an
            ``"id"`` key holding the subject's DID.
        additional_types:
            Extra strings to append to the ``type`` array. The first element
            is always ``"VerifiableCredential"``.
        issuance_date:
            UTC datetime for ``issuanceDate``. Defaults to the current UTC
            time when not provided.
        expiration_date:
            Optional UTC datetime for ``expirationDate``.

        Returns
        -------
        VerifiableCredential
            A fully-formed credential with an attached Ed25519 proof.

        Raises
        ------
        VerificationError
            If signing fails due to a key material problem.
        """
        now = issuance_date or datetime.now(tz=timezone.utc)
        issuance_str = _format_datetime(now)
        expiration_str = _format_datetime(expiration_date) if expiration_date else None

        vc_types = [_BASE_TYPE] + (additional_types or [])

        # Build the unsigned credential to obtain canonical bytes for signing.
        unsigned = VerifiableCredential(
            context=_VC_CONTEXT,
            id=credential_id,
            type=vc_types,
            issuer=self._issuer_did,
            issuance_date=issuance_str,
            credential_subject=subject,
            expiration_date=expiration_str,
            proof=None,
        )

        canonical = canonicalize_credential(unsigned)
        signature = self._sign(canonical)
        proof_value = _encode_base64url(signature)

        proof = CredentialProof(
            type=ProofType.ED25519_SIGNATURE_2020,
            created=issuance_str,
            verification_method=self._verification_method_id,
            proof_purpose="assertionMethod",
            proof_value=proof_value,
        )

        return VerifiableCredential(
            context=unsigned.context,
            id=unsigned.id,
            type=unsigned.type,
            issuer=unsigned.issuer,
            issuance_date=unsigned.issuance_date,
            credential_subject=unsigned.credential_subject,
            expiration_date=unsigned.expiration_date,
            proof=proof,
        )

    def _sign(self, message: bytes) -> bytes:
        """Return a 64-byte Ed25519 signature over *message*."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError as exc:
            raise VerificationError(
                "CredentialIssuer._sign: 'cryptography' package is required "
                "for signing; install aumos-agent-identity[sign]"
            ) from exc

        try:
            if len(self._private_key_bytes) == 32:
                private_key = Ed25519PrivateKey.from_private_bytes(self._private_key_bytes)
            else:
                # 64-byte expanded key: first 32 bytes are the seed.
                private_key = Ed25519PrivateKey.from_private_bytes(
                    self._private_key_bytes[:32]
                )
            return private_key.sign(message)
        except Exception as exc:
            raise VerificationError(f"CredentialIssuer._sign failed: {exc}") from exc


# ------------------------------------------------------------------
# Standalone helpers (used by both CredentialIssuer and verification.py)
# ------------------------------------------------------------------


def canonicalize_credential(vc: VerifiableCredential) -> bytes:
    """Return the canonical JSON bytes of a credential, omitting the proof.

    This is the byte sequence that was signed during issuance and must be
    reconstructed identically during verification. The serialization uses
    deterministic key ordering and no whitespace.

    Parameters
    ----------
    vc:
        The credential to canonicalize. The ``proof`` field is excluded.

    Returns
    -------
    bytes
        UTF-8 encoded JSON with keys in insertion order matching the
        original credential construction order.
    """
    doc: dict[str, Any] = {
        "@context": vc.context,
        "id": vc.id,
        "type": vc.type,
        "issuer": vc.issuer,
        "issuanceDate": vc.issuance_date,
    }
    if vc.expiration_date is not None:
        doc["expirationDate"] = vc.expiration_date
    doc["credentialSubject"] = vc.credential_subject

    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_proof_value(proof: CredentialProof) -> bytes:
    """Decode the base64url ``proofValue`` from a credential proof.

    Parameters
    ----------
    proof:
        The :class:`~types.CredentialProof` whose ``proof_value`` to decode.

    Returns
    -------
    bytes
        Raw signature bytes (64 bytes for Ed25519).

    Raises
    ------
    VerificationError
        If the proof value is not valid base64url.
    """
    try:
        return _decode_base64url(proof.proof_value)
    except Exception as exc:
        raise VerificationError(
            f"decode_proof_value: invalid base64url in proof_value: {exc}"
        ) from exc


def validate_credential_structure(raw: object) -> VerifiableCredential:
    """Parse and validate a raw JSON-decoded object as a VerifiableCredential.

    Performs structural validation only — no cryptographic checks.

    Parameters
    ----------
    raw:
        The JSON-decoded Python object (expected to be a dict).

    Returns
    -------
    VerifiableCredential

    Raises
    ------
    VerificationError
        If the object is missing required fields or has invalid field types.
    """
    if not isinstance(raw, dict):
        raise VerificationError(
            f"validate_credential_structure: expected dict, got {type(raw).__name__}"
        )

    for field_name in ("type", "issuer", "issuanceDate", "credentialSubject"):
        if field_name not in raw:
            raise VerificationError(
                f"validate_credential_structure: missing required field {field_name!r}"
            )

    vc_type = raw.get("type")
    if not isinstance(vc_type, list) or _BASE_TYPE not in vc_type:
        raise VerificationError(
            'validate_credential_structure: "type" must be a list containing '
            '"VerifiableCredential"'
        )

    if not isinstance(raw.get("issuer"), str):
        raise VerificationError(
            'validate_credential_structure: "issuer" must be a string'
        )

    if not isinstance(raw.get("credentialSubject"), dict):
        raise VerificationError(
            'validate_credential_structure: "credentialSubject" must be an object'
        )

    context_raw = raw.get("@context", [])
    context: list[str] = (
        list(context_raw) if isinstance(context_raw, list) else [str(context_raw)]
    )

    proof_raw = raw.get("proof")
    proof: CredentialProof | None = None
    if isinstance(proof_raw, dict):
        try:
            proof_type = ProofType(proof_raw.get("type", ""))
        except ValueError as exc:
            raise VerificationError(
                f"validate_credential_structure: unsupported proof type "
                f"{proof_raw.get('type')!r}"
            ) from exc

        proof = CredentialProof(
            type=proof_type,
            created=str(proof_raw.get("created", "")),
            verification_method=str(proof_raw.get("verificationMethod", "")),
            proof_purpose=str(proof_raw.get("proofPurpose", "")),
            proof_value=str(proof_raw.get("proofValue", "")),
        )

    return VerifiableCredential(
        context=context,
        id=str(raw.get("id", "")),
        type=list(vc_type),
        issuer=str(raw["issuer"]),
        issuance_date=str(raw["issuanceDate"]),
        credential_subject=dict(raw["credentialSubject"]),
        expiration_date=raw.get("expirationDate"),
        proof=proof,
    )


def extract_subject_id(credential_subject: dict[str, Any]) -> str | None:
    """Return the ``id`` field from a credential subject if present.

    Parameters
    ----------
    credential_subject:
        The ``credentialSubject`` dict from a :class:`~types.VerifiableCredential`.

    Returns
    -------
    str or None
    """
    subject_id = credential_subject.get("id")
    return str(subject_id) if isinstance(subject_id, str) else None


# ------------------------------------------------------------------
# Internal base64url utilities (no external dependencies)
# ------------------------------------------------------------------


def _encode_base64url(data: bytes) -> str:
    """Encode *data* as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_base64url(encoded: str) -> bytes:
    """Decode a base64url string (with or without padding)."""
    # Restore padding.
    remainder = len(encoded) % 4
    if remainder == 2:
        encoded += "=="
    elif remainder == 3:
        encoded += "="
    return base64.urlsafe_b64decode(encoded)


def _format_datetime(dt: datetime) -> str:
    """Format a datetime as an ISO 8601 UTC string ending with ``Z``."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

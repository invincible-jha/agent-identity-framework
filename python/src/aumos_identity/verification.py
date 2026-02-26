# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""Credential verification — signature checking and expiry validation.

This module is the *consumption* counterpart to :mod:`credential`. It
provides two entry points:

``verify_credential_signature``
    Full end-to-end verification: resolves the issuer DID, extracts the
    Ed25519 public key, reconstructs the canonical document, and checks the
    cryptographic signature.

``check_expiry``
    Lightweight expiry check that requires no network call and no
    cryptographic operations.

DID resolution strategy
-----------------------
- **did:key** — entirely offline. The public key is derived directly from
  the DID string; no HTTP fetch is made.
- **did:web** — the DID document is fetched from the well-known HTTPS URL
  using the provided ``httpx.AsyncClient``.

Neither method requires a running agent-identity-framework server.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .credential import (
    canonicalize_credential,
    decode_proof_value,
    extract_subject_id,
)
from .did import (
    build_key_did_document,
    extract_public_key_from_document,
    extract_public_key_from_key_did,
    parse_did_document,
    parse_did_method,
    web_did_to_url,
)
from .types import (
    DIDDocument,
    DIDMethod,
    DIDResolutionError,
    ProofType,
    VerifiableCredential,
    VerificationError,
    VerificationResult,
)

if TYPE_CHECKING:
    import httpx


async def verify_credential_signature(
    vc: VerifiableCredential,
    *,
    http_client: "httpx.AsyncClient | None" = None,
    timeout: float = 10.0,
) -> VerificationResult:
    """Verify the Ed25519 proof attached to a Verifiable Credential.

    This function:

    1. Checks that a proof is present and is of type ``Ed25519Signature2020``.
    2. Runs an expiry check via :func:`check_expiry`.
    3. Resolves the issuer DID to obtain its Ed25519 public key.
    4. Reconstructs the canonical credential document (without proof).
    5. Verifies the Ed25519 signature.

    Parameters
    ----------
    vc:
        The credential to verify.
    http_client:
        An :class:`httpx.AsyncClient` used for ``did:web`` document
        resolution. When ``None``, a temporary client is created for this
        call. For ``did:key`` credentials, no client is used.
    timeout:
        Timeout in seconds for outbound HTTP fetches (``did:web`` only).

    Returns
    -------
    VerificationResult
        This function never raises on cryptographic failure — failures are
        returned as ``VerificationResult(valid=False, reason=...)``.

    Raises
    ------
    VerificationError
        Only when the credential is structurally malformed (e.g., missing
        proof entirely after passing ``None``-proof check, or if the
        cryptography library is not installed).
    """

    def failure(reason: str) -> VerificationResult:
        return VerificationResult(
            valid=False,
            issuer_did=vc.issuer,
            credential_id=vc.id,
            reason=reason,
        )

    # --- Step 1: Proof presence and type. ---
    if vc.proof is None:
        return failure("credential has no proof")

    if vc.proof.type is not ProofType.ED25519_SIGNATURE_2020:
        return failure(f"unsupported proof type: {vc.proof.type.value!r}")

    # --- Step 2: Expiry check. ---
    expiry_result = check_expiry(vc)
    if not expiry_result.valid:
        return expiry_result

    expires_at = expiry_result.expires_at

    # --- Step 3: DID resolution. ---
    try:
        doc = await _resolve_did_document(vc.issuer, http_client, timeout)
    except (DIDResolutionError, ValueError) as exc:
        return failure(f"DID resolution failed: {exc}")

    # --- Step 4: Public key extraction. ---
    try:
        public_key_bytes = extract_public_key_from_document(doc)
    except ValueError as exc:
        return failure(f"extract public key: {exc}")

    # --- Step 5: Signature verification. ---
    try:
        signature = decode_proof_value(vc.proof)
    except VerificationError as exc:
        return failure(f"decode proof value: {exc}")

    if len(signature) != 64:
        return failure(f"unexpected signature length: {len(signature)} (expected 64)")

    canonical = canonicalize_credential(vc)

    try:
        is_valid = _verify_ed25519(public_key_bytes, signature, canonical)
    except VerificationError as exc:
        raise
    except Exception as exc:
        raise VerificationError(f"Ed25519 verification error: {exc}") from exc

    if not is_valid:
        return failure("Ed25519 signature is invalid")

    subject_id = extract_subject_id(vc.credential_subject)

    return VerificationResult(
        valid=True,
        issuer_did=vc.issuer,
        credential_id=vc.id,
        subject_id=subject_id,
        expires_at=expires_at,
    )


def check_expiry(vc: VerifiableCredential) -> VerificationResult:
    """Check whether a Verifiable Credential has expired.

    This is a pure, synchronous function — no network call, no cryptography.

    Parameters
    ----------
    vc:
        The credential whose expiry date to inspect.

    Returns
    -------
    VerificationResult
        ``valid=True`` when the credential has not expired or has no
        expiry date. ``valid=False`` with ``reason="credential has expired"``
        when past the expiration date.

    Examples
    --------
    >>> result = check_expiry(vc)
    >>> if not result.valid:
    ...     print(result.reason)
    credential has expired
    """
    if vc.expiration_date is None:
        return VerificationResult(
            valid=True,
            issuer_did=vc.issuer,
            credential_id=vc.id,
        )

    try:
        expires_at = _parse_iso8601(vc.expiration_date)
    except ValueError as exc:
        return VerificationResult(
            valid=False,
            issuer_did=vc.issuer,
            credential_id=vc.id,
            reason=f"invalid expirationDate format: {exc}",
        )

    if datetime.now(tz=timezone.utc) > expires_at:
        return VerificationResult(
            valid=False,
            issuer_did=vc.issuer,
            credential_id=vc.id,
            expires_at=expires_at,
            reason="credential has expired",
        )

    return VerificationResult(
        valid=True,
        issuer_did=vc.issuer,
        credential_id=vc.id,
        expires_at=expires_at,
    )


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


async def _resolve_did_document(
    did: str,
    http_client: "httpx.AsyncClient | None",
    timeout: float,
) -> DIDDocument:
    """Resolve a DID document for either ``did:key`` or ``did:web``."""
    method = parse_did_method(did)  # Raises UnsupportedDIDMethodError.

    if method is DIDMethod.KEY:
        # Entirely offline: derive the document from the DID string.
        public_key = extract_public_key_from_key_did(did)
        return build_key_did_document(did, public_key)

    # did:web: fetch the document from the well-known HTTPS URL.
    url = web_did_to_url(did)
    return await _fetch_did_document(url, did, http_client, timeout)


async def _fetch_did_document(
    url: str,
    expected_did: str,
    http_client: "httpx.AsyncClient | None",
    timeout: float,
) -> DIDDocument:
    """Fetch and parse a DID document from an HTTPS URL."""
    try:
        import httpx as _httpx
    except ImportError as exc:
        raise VerificationError(
            "httpx is required for did:web resolution; "
            "install aumos-agent-identity"
        ) from exc

    owned_client = http_client is None
    client: _httpx.AsyncClient = http_client or _httpx.AsyncClient()

    try:
        try:
            response = await client.get(
                url,
                headers={"Accept": "application/json"},
                timeout=timeout,
            )
        except _httpx.TimeoutException as exc:
            raise DIDResolutionError(
                f"timeout fetching DID document from {url}"
            ) from exc
        except _httpx.RequestError as exc:
            raise DIDResolutionError(
                f"network error fetching DID document from {url}: {exc}"
            ) from exc

        if not response.is_success:
            raise DIDResolutionError(
                f"HTTP {response.status_code} fetching DID document from {url}"
            )

        try:
            raw = response.json()
        except Exception as exc:
            raise DIDResolutionError(
                f"failed to parse DID document JSON from {url}: {exc}"
            ) from exc

        try:
            return parse_did_document(raw, expected_did=expected_did)
        except ValueError as exc:
            raise DIDResolutionError(str(exc)) from exc

    finally:
        if owned_client:
            await client.aclose()


def _verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature using the ``cryptography`` package.

    Parameters
    ----------
    public_key:
        Raw 32-byte Ed25519 public key.
    signature:
        Raw 64-byte Ed25519 signature.
    message:
        The signed message bytes.

    Returns
    -------
    bool
        ``True`` if the signature is valid.

    Raises
    ------
    VerificationError
        If the ``cryptography`` package is not installed, or if the key
        material is structurally invalid.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise VerificationError(
            "_verify_ed25519: 'cryptography' package is required; "
            "install aumos-agent-identity"
        ) from exc

    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError as exc:
        raise VerificationError(
            f"_verify_ed25519: invalid public key ({len(public_key)} bytes): {exc}"
        ) from exc

    try:
        key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def _parse_iso8601(date_string: str) -> datetime:
    """Parse an ISO 8601 datetime string to a timezone-aware ``datetime``.

    Handles the trailing ``Z`` suffix used by W3C VC dates.
    """
    normalized = date_string.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

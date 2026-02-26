# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""DID document types, parsing, and derivation utilities."""

from __future__ import annotations

import base64
import re
from urllib.parse import urlparse

from .types import (
    DIDDocument,
    DIDMethod,
    UnsupportedDIDMethodError,
    VerificationMethod,
    VerificationMethodType,
)

# Multicodec prefix for Ed25519 public keys: 0xed 0x01
_ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])

# Base58btc alphabet (Bitcoin alphabet)
_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode_base58btc(data: bytes) -> str:
    """Encode bytes as base58btc (Bitcoin alphabet, no multibase prefix)."""
    count = 0
    for byte in data:
        if byte != 0:
            break
        count += 1

    n = int.from_bytes(data, "big")
    result = b""
    while n > 0:
        n, remainder = divmod(n, 58)
        result = bytes([_BASE58_ALPHABET[remainder]]) + result

    return (b"1" * count + result).decode("ascii")


def decode_base58btc(encoded: str) -> bytes:
    """Decode a base58btc string (no multibase prefix) to bytes."""
    n = 0
    for char in encoded:
        index = _BASE58_ALPHABET.find(char.encode("ascii"))
        if index < 0:
            raise ValueError(f"Invalid base58btc character: {char!r}")
        n = n * 58 + index

    leading_zeros = len(encoded) - len(encoded.lstrip("1"))
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    return b"\x00" * leading_zeros + raw


def derive_key_did(public_key: bytes) -> str:
    """Derive a did:key DID from a raw 32-byte Ed25519 public key.

    Encoding: ``did:key:z`` + base58btc(0xed01 || public_key_bytes)
    """
    if len(public_key) != 32:
        raise ValueError(
            f"derive_key_did: expected 32-byte Ed25519 public key, got {len(public_key)}"
        )
    prefixed = _ED25519_MULTICODEC_PREFIX + public_key
    return "did:key:z" + encode_base58btc(prefixed)


def extract_public_key_from_key_did(did: str) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from a did:key DID."""
    if not did.startswith("did:key:z"):
        raise ValueError(
            f"extract_public_key_from_key_did: not a base58btc did:key: {did}"
        )
    encoded = did[len("did:key:z"):]
    decoded = decode_base58btc(encoded)

    if len(decoded) < len(_ED25519_MULTICODEC_PREFIX):
        raise ValueError("extract_public_key_from_key_did: decoded bytes too short")

    prefix = decoded[: len(_ED25519_MULTICODEC_PREFIX)]
    if prefix != _ED25519_MULTICODEC_PREFIX:
        raise ValueError(
            f"extract_public_key_from_key_did: unexpected multicodec prefix {prefix.hex()}"
        )

    raw_key = decoded[len(_ED25519_MULTICODEC_PREFIX):]
    if len(raw_key) != 32:
        raise ValueError(
            f"extract_public_key_from_key_did: expected 32 key bytes, got {len(raw_key)}"
        )
    return raw_key


def parse_did_method(did: str) -> DIDMethod:
    """Extract and return the DID method. Only 'key' and 'web' are supported."""
    parts = did.split(":", 2)
    if len(parts) < 3 or parts[0] != "did":
        raise ValueError(f"parse_did_method: invalid DID: {did!r}")
    method = parts[1]
    if method == "key":
        return DIDMethod.KEY
    if method == "web":
        return DIDMethod.WEB
    raise UnsupportedDIDMethodError(f"unsupported DID method: {method!r}")


def web_did_to_url(did: str) -> str:
    """Convert a did:web DID to the canonical HTTPS URL for its DID document.

    Examples::

        did:web:example.com             -> https://example.com/.well-known/did.json
        did:web:example.com:agents:abc  -> https://example.com/agents/abc/did.json
    """
    without_scheme = did[len("did:web:"):]
    if not without_scheme:
        raise ValueError(f"web_did_to_url: empty did:web host in: {did!r}")

    colon_pos = without_scheme.find(":")
    if colon_pos < 0:
        host = without_scheme.replace("%3A", ":").replace("%3a", ":")
        return f"https://{host}/.well-known/did.json"

    host = without_scheme[:colon_pos].replace("%3A", ":").replace("%3a", ":")
    path_part = without_scheme[colon_pos + 1:].replace(":", "/")
    return f"https://{host}/{path_part}/did.json"


def extract_public_key_from_document(doc: DIDDocument) -> bytes:
    """Extract the first Ed25519 public key from a DID document.

    Returns the raw 32-byte key.
    """
    for vm in doc.verification_method:
        if vm.type != VerificationMethodType.ED25519_2020:
            continue
        if not vm.public_key_multibase.startswith("z"):
            raise ValueError(
                f"extract_public_key_from_document: expected base58btc multibase (prefix 'z'), "
                f"got {vm.public_key_multibase[:1]!r}"
            )
        decoded = decode_base58btc(vm.public_key_multibase[1:])
        if len(decoded) != 32:
            raise ValueError(
                f"extract_public_key_from_document: unexpected key length {len(decoded)}"
            )
        return decoded

    raise ValueError(
        f"extract_public_key_from_document: no Ed25519VerificationKey2020 "
        f"in document for {doc.id}"
    )


def build_key_did_document(did: str, public_key: bytes) -> DIDDocument:
    """Synthesize a DIDDocument for a did:key DID from its raw public key bytes.

    No network call is required. The document is constructed according to the
    did:key specification: one Ed25519VerificationKey2020 verification method,
    referenced in both ``authentication`` and ``assertionMethod``.

    Parameters
    ----------
    did:
        The fully-qualified ``did:key`` DID string.
    public_key:
        Raw 32-byte Ed25519 public key.

    Returns
    -------
    DIDDocument
    """
    if len(public_key) != 32:
        raise ValueError(
            f"build_key_did_document: expected 32-byte Ed25519 public key, "
            f"got {len(public_key)}"
        )
    # Multibase base58btc encoding: prefix 'z' + base58btc(0xed01 || public_key)
    prefixed = _ED25519_MULTICODEC_PREFIX + public_key
    public_key_multibase = "z" + encode_base58btc(prefixed)
    vm_id = f"{did}#key-1"

    verification_method = VerificationMethod(
        id=vm_id,
        type=VerificationMethodType.ED25519_2020,
        controller=did,
        public_key_multibase=public_key_multibase,
    )

    return DIDDocument(
        context=[
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        id=did,
        verification_method=[verification_method],
        authentication=[vm_id],
        assertion_method=[vm_id],
    )


def parse_did_document(raw: object, expected_did: str) -> DIDDocument:
    """Parse and validate a raw JSON-decoded object as a DIDDocument."""
    if not isinstance(raw, dict):
        raise ValueError(f"parse_did_document: expected dict, got {type(raw).__name__}")

    doc_id = raw.get("id")
    if doc_id != expected_did:
        raise ValueError(
            f"parse_did_document: document id {doc_id!r} does not match "
            f"requested DID {expected_did!r}"
        )

    raw_vms = raw.get("verificationMethod", [])
    if not isinstance(raw_vms, list):
        raise ValueError("parse_did_document: verificationMethod is not a list")

    verification_methods: list[VerificationMethod] = []
    for vm_raw in raw_vms:
        if not isinstance(vm_raw, dict):
            continue
        vm_type_str = vm_raw.get("type", "")
        try:
            vm_type = VerificationMethodType(vm_type_str)
        except ValueError:
            continue  # Skip unsupported verification method types.
        verification_methods.append(
            VerificationMethod(
                id=str(vm_raw.get("id", "")),
                type=vm_type,
                controller=str(vm_raw.get("controller", "")),
                public_key_multibase=str(vm_raw.get("publicKeyMultibase", "")),
            )
        )

    context_raw = raw.get("@context", [])
    context = list(context_raw) if isinstance(context_raw, list) else [str(context_raw)]

    auth_raw = raw.get("authentication", [])
    auth = list(auth_raw) if isinstance(auth_raw, list) else []

    assertion_raw = raw.get("assertionMethod", [])
    assertion = list(assertion_raw) if isinstance(assertion_raw, list) else []

    return DIDDocument(
        context=context,
        id=str(doc_id),
        verification_method=verification_methods,
        authentication=[str(a) for a in auth],
        assertion_method=[str(a) for a in assertion],
        created=raw.get("created"),
        updated=raw.get("updated"),
    )

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""IdentityClient — async HTTP client for the agent-identity-framework REST API.

The client covers two distinct concerns:

1. **Server-backed operations** — resolving AgentIdentity records and DID
   documents from a running agent-identity-framework server via its REST API.
2. **Local verification** — verifying Verifiable Credentials without a
   network round-trip to the identity server (DID document resolution for
   did:web issuers still requires an outbound HTTPS fetch; did:key is
   fully offline).

For did:key DID derivation and DID document utilities, see :mod:`did`.
For credential issuance, see :mod:`credential`.
For standalone verification helpers, see :mod:`verification`.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from .did import parse_did_document, parse_did_method
from .types import (
    AgentIdentity,
    DIDDocument,
    DIDMethod,
    DIDResolutionError,
    IdentityClientError,
    IdentityStatus,
    UnsupportedDIDMethodError,
    VerifiableCredential,
    VerificationResult,
)
from .verification import verify_credential_signature


class IdentityClient:
    """Async client for the agent-identity-framework REST API.

    All methods that call the remote server are coroutines and must be
    awaited. Credential verification is handled locally; no server round-trip
    is needed for :meth:`verify_credential`.

    Parameters
    ----------
    base_url:
        Root URL of the identity server, e.g. ``"https://identity.example.com"``.
        A trailing slash is stripped automatically.
    timeout:
        Per-request timeout in seconds. Defaults to 10.
    http_client:
        Optional pre-configured :class:`httpx.AsyncClient`. When provided,
        ``base_url`` and ``timeout`` are applied on top of it. Useful for
        injecting test transports or custom SSL contexts.

    Examples
    --------
    >>> client = IdentityClient(base_url="https://identity.example.com")
    >>> identity = await client.resolve_identity("did:key:z6Mk...")
    >>> doc = await client.resolve_did_document("did:key:z6Mk...")
    >>> result = await client.verify_credential(vc)
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._owned_client = http_client is None
        self._http = http_client or httpx.AsyncClient(
            base_url=self._base_url,
            timeout=timeout,
            headers={"Accept": "application/json"},
        )

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "IdentityClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP client if it was created internally."""
        if self._owned_client:
            await self._http.aclose()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def create_identity(
        self,
        *,
        owner_did: str,
        did_method: DIDMethod = DIDMethod.KEY,
        web_host: str | None = None,
        web_path: str | None = None,
        ttl_seconds: int | None = None,
    ) -> AgentIdentity:
        """Request the server to create a new agent identity.

        The server generates an Ed25519 key pair, derives the DID, persists
        the record, and returns the resulting :class:`~types.AgentIdentity`.

        Parameters
        ----------
        owner_did:
            The DID of the entity that owns this agent identity. Required.
        did_method:
            Which DID method to use. Defaults to :attr:`~types.DIDMethod.KEY`.
        web_host:
            Required when *did_method* is ``DIDMethod.WEB``. The hostname
            component of the resulting ``did:web`` DID.
        web_path:
            Optional path suffix for ``did:web`` DIDs, e.g. ``"agents/my-bot"``.
        ttl_seconds:
            How long the identity remains valid, in seconds. The server uses
            its configured default (typically 86 400 seconds / 24 hours) when
            this is omitted.

        Returns
        -------
        AgentIdentity
            The newly created identity record.

        Raises
        ------
        ValueError
            If *owner_did* is empty, or if *web_host* is missing for
            ``did:web`` identities.
        IdentityClientError
            If the server returns a non-2xx response.
        """
        if not owner_did:
            raise ValueError("create_identity: owner_did must not be empty")
        if did_method is DIDMethod.WEB and not web_host:
            raise ValueError("create_identity: web_host is required for did:web identities")

        payload: dict[str, Any] = {
            "ownerDid": owner_did,
            "didMethod": did_method.value,
        }
        if web_host:
            payload["webHost"] = web_host
        if web_path:
            payload["webPath"] = web_path
        if ttl_seconds is not None:
            payload["ttlSeconds"] = ttl_seconds

        raw = await self._post("/v1/identities", payload)
        return _parse_agent_identity(raw)

    async def resolve_identity(self, did: str) -> AgentIdentity:
        """Retrieve an :class:`~types.AgentIdentity` record by DID.

        This calls the server's ``GET /v1/identities/{did}`` endpoint. It is
        distinct from DID document resolution — the server returns its internal
        identity record, not a raw DID document.

        Parameters
        ----------
        did:
            The fully-qualified DID to look up, e.g. ``"did:key:z6Mk..."``.

        Returns
        -------
        AgentIdentity

        Raises
        ------
        IdentityClientError
            On non-2xx responses (404 if the identity does not exist).
        """
        raw = await self._get(f"/v1/identities/{_encode_did(did)}")
        return _parse_agent_identity(raw)

    async def resolve_did_document(self, did: str) -> DIDDocument:
        """Fetch and validate a DID document from the identity server.

        For ``did:key`` DIDs, prefer using the local utilities in
        :mod:`did` directly — no network call is needed.

        For ``did:web`` DIDs, the server fetches the document from the
        well-known HTTPS URL and caches it.

        Parameters
        ----------
        did:
            The DID to resolve.

        Returns
        -------
        DIDDocument

        Raises
        ------
        IdentityClientError
            On HTTP errors from the server.
        DIDResolutionError
            If the server returns a document that fails validation.
        UnsupportedDIDMethodError
            If the DID method is not ``did:key`` or ``did:web``.
        """
        parse_did_method(did)  # Raises UnsupportedDIDMethodError early.
        raw = await self._get(f"/v1/dids/{_encode_did(did)}")
        try:
            return parse_did_document(raw, expected_did=did)
        except ValueError as exc:
            raise DIDResolutionError(str(exc)) from exc

    async def verify_credential(
        self,
        vc: VerifiableCredential,
        *,
        timeout: float | None = None,
    ) -> VerificationResult:
        """Verify a Verifiable Credential using the local verification engine.

        Verification is performed entirely client-side:

        - For ``did:key`` issuers, the public key is derived from the DID
          without any network call.
        - For ``did:web`` issuers, the DID document is fetched from the
          well-known HTTPS URL using the internal HTTP client.

        No server round-trip to the identity server is made.

        Parameters
        ----------
        vc:
            The credential to verify. Must carry a valid
            :class:`~types.CredentialProof`.
        timeout:
            Override the client-level timeout for this call only (seconds).

        Returns
        -------
        VerificationResult
            Always returned — never raises on verification failure. Check
            :attr:`~types.VerificationResult.valid` and
            :attr:`~types.VerificationResult.reason`.

        Raises
        ------
        VerificationError
            Only when the credential is structurally malformed (not on
            cryptographic failure, which sets ``valid=False``).
        """
        return await verify_credential_signature(
            vc,
            http_client=self._http,
            timeout=timeout if timeout is not None else self._timeout,
        )

    async def list_identities(self) -> list[AgentIdentity]:
        """List all agent identities registered with the server.

        Returns
        -------
        list[AgentIdentity]

        Raises
        ------
        IdentityClientError
            On non-2xx responses.
        """
        raw = await self._get("/v1/identities")
        if not isinstance(raw, list):
            raise IdentityClientError(
                status_code=0,
                endpoint="/v1/identities",
                message="expected JSON array in list response",
            )
        return [_parse_agent_identity(item) for item in raw]

    # ------------------------------------------------------------------
    # Private HTTP helpers
    # ------------------------------------------------------------------

    async def _get(self, path: str) -> Any:
        url = f"{self._base_url}{path}"
        try:
            response = await self._http.get(url, headers={"Accept": "application/json"})
        except httpx.TimeoutException as exc:
            raise IdentityClientError(
                status_code=0, endpoint=url, message=f"request timed out: {exc}"
            ) from exc

        _raise_for_status(response, url)
        return response.json()

    async def _post(self, path: str, payload: dict[str, Any]) -> Any:
        url = f"{self._base_url}{path}"
        try:
            response = await self._http.post(
                url,
                content=json.dumps(payload).encode(),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
        except httpx.TimeoutException as exc:
            raise IdentityClientError(
                status_code=0, endpoint=url, message=f"request timed out: {exc}"
            ) from exc

        _raise_for_status(response, url)
        return response.json()


# ------------------------------------------------------------------
# Module-level parsing helpers
# ------------------------------------------------------------------


def _encode_did(did: str) -> str:
    """URL-encode a DID for safe inclusion in a path segment."""
    # Colons are not safe in path segments; encode them as %3A.
    return did.replace(":", "%3A")


def _raise_for_status(response: httpx.Response, url: str) -> None:
    if response.is_success:
        return
    message = response.reason_phrase or "unknown error"
    try:
        body = response.json()
        if isinstance(body, dict) and isinstance(body.get("error"), str):
            message = body["error"]
    except Exception:
        pass
    raise IdentityClientError(
        status_code=response.status_code,
        endpoint=url,
        message=message,
    )


_REQUIRED_IDENTITY_FIELDS = frozenset(
    ["did", "ownerDid", "publicKeyBase64", "createdAt", "expiresAt", "status"]
)


def _parse_agent_identity(raw: Any) -> AgentIdentity:
    """Parse a JSON-decoded dict into an :class:`~types.AgentIdentity`.

    Raises
    ------
    ValueError
        If any required field is missing or has the wrong type.
    """
    if not isinstance(raw, dict):
        raise ValueError(
            f"_parse_agent_identity: expected dict, got {type(raw).__name__}"
        )

    missing = _REQUIRED_IDENTITY_FIELDS - raw.keys()
    if missing:
        raise ValueError(
            f"_parse_agent_identity: missing required fields: {sorted(missing)}"
        )

    for field_name in _REQUIRED_IDENTITY_FIELDS:
        if not isinstance(raw[field_name], str):
            raise ValueError(
                f"_parse_agent_identity: field {field_name!r} must be a string, "
                f"got {type(raw[field_name]).__name__}"
            )

    try:
        status = IdentityStatus(raw["status"])
    except ValueError as exc:
        raise ValueError(
            f"_parse_agent_identity: unknown status value {raw['status']!r}"
        ) from exc

    return AgentIdentity(
        did=raw["did"],
        owner_did=raw["ownerDid"],
        public_key_base64=raw["publicKeyBase64"],
        created_at=raw["createdAt"],
        expires_at=raw["expiresAt"],
        status=status,
    )

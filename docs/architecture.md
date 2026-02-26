# Architecture Overview

`agent-identity-framework` is a multi-language SDK for issuing and verifying
cryptographic identities for AI agents. It is not a trust-scoring or behavioural
analysis system. It provides the *identity primitive* on which other systems
(e.g. resource governance, audit logging) can build.

## Layers

```
┌──────────────────────────────────────────────────────────────────┐
│                         Application Layer                        │
│   Your AI agent, orchestrator, or API service                    │
└────────────────┬───────────────────────┬────────────────────────┘
                 │                       │
    ┌────────────▼──────┐   ┌────────────▼──────┐
    │  TypeScript SDK   │   │    Python SDK      │
    │  @aumos/agent-    │   │  aumos-agent-      │
    │  identity         │   │  identity          │
    └────────────┬──────┘   └────────────┬──────┘
                 │                       │
                 └──────────┬────────────┘
                            │  REST API (JSON over HTTPS)
                  ┌─────────▼──────────┐
                  │    Go Core Server   │
                  │  identity manager   │
                  │  key manager        │
                  │  DID resolver       │
                  └─────────┬──────────┘
                            │
                  ┌─────────▼──────────┐
                  │   Key Storage       │
                  │  InMemoryKeyStore  │
                  │  FileKeyStore      │
                  └────────────────────┘
```

## Go Core (`go/`)

The Go implementation is the canonical reference and the component that runs
as a server in production deployments.

| Package         | Responsibility                                              |
|-----------------|-------------------------------------------------------------|
| `identity`      | `AgentIdentity` struct, `IdentityManager`, VC issuance      |
| `spiffe`        | Workload identity adapter, SVID bridging                    |
| `keys`          | `KeyManager` interface, Ed25519 impl, key rotation          |
| `types`         | Shared value types and error types                          |

`IdentityManager` is the primary service object. All exported methods are safe
for concurrent use. Construct it via `NewIdentityManager(opts)`:

```go
store := identity.NewInMemoryStore()
manager, err := identity.NewIdentityManager(identity.ManagerOptions{
    Store: store,
})
agent, err := manager.CreateIdentity(ctx, identity.CreateOptions{
    OwnerDID:  "did:key:z6Mk...",
    DIDMethod: types.DIDMethodKey,
    TTL:       24 * time.Hour,
})
```

### REST API Surface

The Go server exposes a versioned REST API under `/v1/`:

| Method | Path                         | Description                               |
|--------|------------------------------|-------------------------------------------|
| `POST` | `/v1/identities`             | Create a new agent identity               |
| `GET`  | `/v1/identities/{did}`       | Retrieve identity record by DID           |
| `GET`  | `/v1/identities`             | List all registered identities            |
| `POST` | `/v1/identities/{did}/revoke`| Mark an identity as revoked               |
| `GET`  | `/v1/dids/{did}`             | Resolve a DID document                    |

All DIDs in path segments are percent-encoded (`did:key:z6Mk...` becomes
`did%3Akey%3Az6Mk...`).

## TypeScript SDK (`typescript/`)

The TypeScript SDK targets browser and Node.js environments. It is an async,
fetch-based client — it does not embed the Go server.

Key responsibilities:

- `IdentityClient` — HTTP client for the Go core REST API.
- `verifyCredential()` — local Ed25519 verification (no server round-trip needed).
- DID utilities — `parseDIDMethod`, `webDIDToURL`, `extractPublicKeyFromKeyDID`.
- Credential utilities — `canonicalizeCredential`, `decodeProofValue`.

**did:key verification is entirely offline.** The public key is derived from
the DID string; no HTTP fetch is made. **did:web verification** fetches the
DID document from the well-known HTTPS URL.

### Relationship to the Go Core

The TypeScript SDK does not replicate identity storage or key generation. For
operations that mutate state (creating or revoking identities), it must call
the Go core server. Verification is always local.

## Python SDK (`python/`)

The Python SDK mirrors the TypeScript SDK in responsibility: it is an async
HTTP client for the Go core REST API, with local credential verification.

Key responsibilities:

- `IdentityClient` — `httpx`-based async client for the Go core REST API.
- `verify_credential_signature()` — local Ed25519 verification.
- `check_expiry()` — pure, synchronous expiry check.
- `CredentialIssuer` — signs and produces W3C Verifiable Credentials.
- DID utilities in `did.py` — `parse_did_method`, `web_did_to_url`,
  `derive_key_did`, `build_key_did_document`.

The Python client uses `cryptography` (PyCA) for Ed25519 operations and
`httpx` for async HTTP.

### Credential Verification Flow (Python)

```
verify_credential_signature(vc)
    │
    ├─ check proof presence and type (Ed25519Signature2020)
    ├─ check_expiry(vc)
    ├─ resolve issuer DID
    │   ├─ did:key  → build_key_did_document()  [offline]
    │   └─ did:web  → fetch HTTPS well-known URL  [network]
    ├─ extract_public_key_from_document(doc)
    ├─ decode_proof_value(vc.proof)
    ├─ canonicalize_credential(vc)  [without proof field]
    └─ Ed25519 verify(signature, canonical, public_key)
```

## Design Decisions

### Why separate Go core and language SDKs?

Key generation and identity persistence require a trusted, server-side
environment. Embedding key storage in a client-side library creates unauditable
key material exposure. The Go core is the single source of truth for identity
records; the language SDKs are read-and-verify clients.

### Why is credential verification local?

Credential verification requires only the issuer's public key, which is
derivable from the DID (for `did:key`) or fetchable from a well-known HTTPS
URL (for `did:web`). Routing verification through the identity server would
create unnecessary latency and a single point of failure for an operation that
can be done without it.

### Why only did:key and did:web?

These two methods cover the full range of deployment patterns without
introducing registry dependencies:

- `did:key` — self-contained, no external infrastructure, suitable for
  ephemeral or short-lived agent identities.
- `did:web` — anchored to a domain owner's HTTPS infrastructure, suitable for
  stable organizational identities.

See [did-methods.md](did-methods.md) for encoding details.

### Why Ed25519 only?

Ed25519 offers strong security, small key and signature sizes (32 and 64 bytes
respectively), and is well-supported across Go (`crypto/ed25519`), Python
(`cryptography`), TypeScript (`@noble/ed25519`), and Rust. Supporting multiple
algorithms increases attack surface with no practical benefit for this use case.

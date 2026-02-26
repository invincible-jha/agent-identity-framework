# Key Management

`agent-identity-framework` uses Ed25519 key pairs for all cryptographic
operations. This document covers key storage options, the rotation workflow,
and operational guidance for key lifecycle management.

## Key Material in This Framework

Each `AgentIdentity` has exactly one active Ed25519 key pair at a time:

- The **private key** is held by the Go core server's `KeyManager`. It is
  used to sign Verifiable Credentials and is never exposed through the API.
- The **public key** appears in the `AgentIdentity` record (as `publicKeyBase64`)
  and in the resolved DID document (as `publicKeyMultibase` in the
  verification method).

The Python and TypeScript SDKs have no access to private keys. Only the Go
core server performs signing operations.

## KeyManager Interface

The Go `keys` package defines a pluggable interface:

```go
type KeyManager interface {
    Generate(ctx context.Context) (*KeyPair, error)
    Get(ctx context.Context, keyID string) (*KeyPair, error)
    Delete(ctx context.Context, keyID string) error
    List(ctx context.Context) ([]string, error)
}
```

Two implementations are shipped with the framework. No TEE or HSM backends
are included — hardware attestation is a separate package.

## InMemoryKeyStore

The `InMemoryKeyStore` holds key pairs in process memory. It is thread-safe
and suitable for:

- Unit tests and integration tests.
- Short-lived agents (single process lifetime).
- Local development.

Key material is lost when the process exits. Do not use this backend for
agents that need to re-establish their identity after a restart.

```go
import "github.com/aumos-ai/agent-identity-framework/keys"

km := keys.NewInMemoryKeyStore()
manager, err := identity.NewIdentityManager(identity.ManagerOptions{
    Store:      identity.NewInMemoryStore(),
    KeyManager: km,
})
```

## FileKeyStore

The `FileKeyStore` persists Ed25519 key pairs to an encrypted JSON file on
disk. Keys are encrypted at rest using AES-256-GCM with a key derived from a
passphrase via Argon2id.

```go
import "github.com/aumos-ai/agent-identity-framework/keys"

km, err := keys.NewFileKeyStore(keys.FileKeyStoreOptions{
    FilePath:   "/var/lib/my-agent/keys.enc",
    Passphrase: []byte(os.Getenv("AGENT_KEY_PASSPHRASE")),
})
if err != nil {
    log.Fatal(err)
}

manager, err := identity.NewIdentityManager(identity.ManagerOptions{
    Store:      identity.NewInMemoryStore(),
    KeyManager: km,
})
```

### File Format

The encrypted file contains a JSON envelope:

```json
{
  "version": 1,
  "kdf": "argon2id",
  "kdf_params": { "time": 1, "memory": 65536, "threads": 4 },
  "salt": "<base64url>",
  "nonce": "<base64url>",
  "ciphertext": "<base64url>"
}
```

The ciphertext decrypts to a JSON object mapping key IDs to base64url-encoded
Ed25519 private key seeds (32 bytes each).

### Passphrase Management

The passphrase must be provided at startup. Options:

- **Environment variable** — Simple, suitable for containers. Ensure the
  variable is set from a secret manager (AWS Secrets Manager, HashiCorp Vault,
  GCP Secret Manager), not a plaintext config file.
- **Secret manager sidecar** — Inject the passphrase as a file at a
  well-known path, then read and clear it after `NewFileKeyStore` returns.

Never store the passphrase in source control, container images, or
unencrypted configuration files.

### File Permissions

Restrict access to the key file:

```bash
chmod 600 /var/lib/my-agent/keys.enc
chown agent-user:agent-group /var/lib/my-agent/keys.enc
```

On Linux, run the Go server process under a dedicated non-root user.

## Key Rotation

Key rotation replaces the active key pair for an agent identity with a new one.
The old key is retained in the `KeyManager` for a configurable overlap period
so that in-flight credentials signed with the old key can still be verified.

Rotation is a manual operation — it is always initiated by the identity owner,
never triggered automatically by the framework.

### Rotation via the Go API

```go
err := manager.RotateKey(ctx, agentDID, identity.RotateKeyOptions{
    OverlapDuration: 24 * time.Hour,
})
```

After rotation:

1. A new Ed25519 key pair is generated and stored.
2. The agent's DID document is updated to reference the new key.
3. The old key remains in the `KeyManager` for `OverlapDuration`.
4. New credentials are signed with the new key.
5. Credentials signed with the old key remain verifiable until the overlap
   period expires, after which the old key can be deleted.

### Rotation via the REST API

```http
POST /v1/identities/did%3Akey%3Az6Mk.../rotate-key
Content-Type: application/json

{
  "overlapSeconds": 86400
}
```

Response: the updated `AgentIdentity` with the new `publicKeyBase64`.

### DID Method Implications

**did:key** encodes the public key directly in the DID string. Rotating the
key changes the DID. The old identity record is marked `revoked` after the
overlap period; a new `AgentIdentity` with the new DID is created. Any
Verifiable Credentials issued under the old DID remain verifiable using the
old key while it is still in the `KeyManager`.

**did:web** is decoupled from the key material — the DID stays the same across
rotations. Only the DID document (hosted at the well-known URL) is updated to
reference the new verification method. This makes `did:web` preferable for
stable, long-lived identities that need seamless key rotation.

## Key Deletion

Delete a key only after confirming that no outstanding credentials reference it
and the overlap period has expired:

```go
err := km.Delete(ctx, keyID)
```

There is no undelete. Deleting the active key for an identity before rotation
is complete will break verification of all credentials issued under that identity.

## Backup and Recovery

For `FileKeyStore`, back up the encrypted key file and store the passphrase
in a separate location (e.g. a secret manager). Recovery requires both the
encrypted file and the passphrase.

For `InMemoryKeyStore` in production, always pair it with a persistent
`IdentityStore` (e.g. a database-backed store). If the process restarts, the
in-memory keys are lost and affected agent identities must be re-created.

## Operational Checklist

- [ ] Use `FileKeyStore` (not `InMemoryKeyStore`) for production deployments.
- [ ] Source the `FileKeyStore` passphrase from a secret manager at startup.
- [ ] Set `chmod 600` and restrict file ownership on the key file.
- [ ] Rotate keys on a defined schedule (e.g. annually, or after any suspected
      compromise).
- [ ] For `did:key` identities, plan for DID changes on key rotation.
- [ ] For `did:web` identities, confirm the DID document is updated and
      propagated before the old key's overlap period expires.
- [ ] Verify that revoked identity records are rejected by all verifying
      parties before cleaning up old key material.

# Supported DID Methods

`agent-identity-framework` supports exactly two DID methods: `did:key` and
`did:web`. No other DID methods will be added to this package. See
[FIRE_LINE.md](../FIRE_LINE.md) for the rationale.

## did:key

`did:key` is a self-contained DID method. The DID encodes the public key
directly in the identifier string — no external registry or HTTP fetch is
needed to resolve it.

### Encoding

The encoding follows the [did:key specification](https://w3c-ccg.github.io/did-method-key/):

1. Take the raw 32-byte Ed25519 public key.
2. Prepend the multicodec varint prefix for Ed25519: `0xed 0x01`.
3. Encode the result with base58btc (Bitcoin alphabet, no padding).
4. Prepend the multibase prefix `z` (indicates base58btc encoding).
5. Prefix with `did:key:`.

```
did:key:z<base58btc(0xed01 || public_key_bytes)>
```

Example:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

### Resolution

`did:key` resolution is entirely offline. Given the DID, the verification
method and DID document are derived without any network call:

```python
from aumos_identity.did import (
    extract_public_key_from_key_did,
    build_key_did_document,
)

public_key = extract_public_key_from_key_did(
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
)
doc = build_key_did_document(
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    public_key,
)
```

```go
publicKey, err := identity.ExtractPublicKeyFromKeyDID(did)
doc := identity.BuildKeyDIDDocument(did, publicKey)
```

```typescript
import { extractPublicKeyFromKeyDID } from "@aumos/agent-identity";
const publicKey = extractPublicKeyFromKeyDID(did);
```

### Synthesized DID Document

The document produced for a `did:key` DID has this structure:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:key:z6Mk...",
  "verificationMethod": [
    {
      "id": "did:key:z6Mk...#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:key:z6Mk...",
      "publicKeyMultibase": "z<base58btc(0xed01 || public_key)>"
    }
  ],
  "authentication": ["did:key:z6Mk...#key-1"],
  "assertionMethod": ["did:key:z6Mk...#key-1"]
}
```

The verification method ID convention is `<did>#key-1`. The public key
multibase value uses the same base58btc encoding as the DID itself, prefixed
with `z`.

### Use Cases

- Short-lived or ephemeral agent identities.
- Air-gapped environments with no external DNS or HTTP access.
- Local development and testing.
- Identities that do not need to be publicly discoverable.

## did:web

`did:web` anchors identity to an HTTPS domain. The DID document is hosted at
a well-known URL under the domain owner's control. No central registry is
involved — the DNS and HTTPS certificate infrastructure serves as the root
of trust.

### DID to URL Mapping

The mapping from a `did:web` DID to its document URL follows the
[did:web specification](https://w3c-ccg.github.io/did-method-web/):

| DID                              | Document URL                                |
|----------------------------------|---------------------------------------------|
| `did:web:example.com`            | `https://example.com/.well-known/did.json`  |
| `did:web:example.com:agents:bot` | `https://example.com/agents/bot/did.json`   |

Colons after the host segment are converted to forward slashes in the URL path.
Percent-encoded colons in the host (`%3A`) are decoded before constructing the URL.

```python
from aumos_identity.did import web_did_to_url

web_did_to_url("did:web:example.com")
# "https://example.com/.well-known/did.json"

web_did_to_url("did:web:example.com:agents:my-bot")
# "https://example.com/agents/my-bot/did.json"
```

### Hosting a DID Document

Serve a valid DID document at the well-known URL with
`Content-Type: application/json`. A minimal example:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:web:example.com",
  "verificationMethod": [
    {
      "id": "did:web:example.com#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:example.com",
      "publicKeyMultibase": "z6MkhaXgBZ..."
    }
  ],
  "authentication": ["did:web:example.com#key-1"],
  "assertionMethod": ["did:web:example.com#key-1"]
}
```

The `id` field in the document must exactly match the DID being resolved.
The framework validates this on every fetch and rejects documents where the
`id` does not match.

### did:web for Agents with Path Segments

For deployments hosting many agent identities under a single domain, use path
segments to distinguish them:

```
did:web:example.com:agents:worker-1
did:web:example.com:agents:worker-2
```

These resolve to:

```
https://example.com/agents/worker-1/did.json
https://example.com/agents/worker-2/did.json
```

When creating a `did:web` identity through the framework:

```go
agent, err := manager.CreateIdentity(ctx, identity.CreateOptions{
    OwnerDID:  "did:key:z6Mk...",
    DIDMethod: types.DIDMethodWeb,
    WebHost:   "example.com",
    WebPath:   "agents/worker-1",
})
```

```python
identity = await client.create_identity(
    owner_did="did:key:z6Mk...",
    did_method=DIDMethod.WEB,
    web_host="example.com",
    web_path="agents/worker-1",
)
```

The server generates a key pair and returns the identity. You are responsible
for publishing the DID document at the indicated URL.

### Security Considerations

- The domain must be under your control. An attacker who gains control of the
  DNS or HTTPS certificate for the domain can substitute any DID document.
- Use DNSSEC and a Certificate Authority with CAA records to reduce the
  blast radius of domain compromise.
- Rotate keys regularly. See [key-management.md](key-management.md).
- The DID document URL must be served over HTTPS. HTTP is not accepted.

### Use Cases

- Stable organizational identities that must be publicly discoverable.
- Identities associated with a product domain.
- Scenarios where the DID needs to be presented to external verifiers who
  cannot install custom resolution software.

## Choosing Between did:key and did:web

| Factor                         | did:key                   | did:web                         |
|--------------------------------|---------------------------|---------------------------------|
| External infrastructure        | None                      | HTTPS + DNS                     |
| Key rotation                   | New DID required          | Update DID document at same URL |
| Publicly discoverable          | No (DID encodes key only) | Yes (via HTTPS)                 |
| Offline resolution             | Yes                       | No                              |
| Suitable for long-lived agents | Limited                   | Yes                             |
| Suitable for ephemeral agents  | Yes                       | Overhead not justified          |

For most production AI agent deployments, start with `did:key` for simplicity
and migrate to `did:web` when stable, externally-verifiable identity is required.

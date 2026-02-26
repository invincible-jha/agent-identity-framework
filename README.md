# agent-identity-framework

SPIFFE/DID-compatible identity issuance and verification for AI agents.

Part of the [AumOS](https://github.com/aumos-ai) open-source ecosystem — Phase 4, Project 4.4.

## Overview

`agent-identity-framework` provides cryptographically verifiable identities for AI agents using two complementary standards:

- **DID (Decentralized Identifiers)** — `did:web` and `did:key` methods for agent identity documents
- **SPIFFE (Secure Production Identity Framework For Everyone)** — workload identity for agents running in infrastructure

Identities are backed by **Ed25519** keys. Credentials follow the **W3C Verifiable Credentials** data model.

## Repository Layout

```
go/          Core library (Go 1.22+)
typescript/  Client SDK (@aumos/agent-identity)
python/      Client SDK (aumos-agent-identity)
docs/        Architecture and integration guides
examples/    Cross-language usage examples
```

## Quick Start (Go)

```go
import "github.com/aumos-ai/agent-identity-framework/identity"

mgr, err := identity.NewIdentityManager(identity.ManagerOptions{
    Store: identity.NewInMemoryStore(),
})

agent, err := mgr.CreateIdentity(ctx, identity.CreateOptions{
    OwnerDID: "did:web:example.com:owners:org-1",
    TTL:      24 * time.Hour,
})

fmt.Println(agent.DID) // did:key:z6Mk...
```

## Quick Start (TypeScript)

```typescript
import { IdentityClient } from "@aumos/agent-identity";

const client = new IdentityClient({ baseURL: "https://your-identity-server" });
const result = await client.resolveIdentity("did:web:example.com:agents:agent-1");
```

## Quick Start (Python)

```python
from aumos_identity import IdentityClient

client = IdentityClient(base_url="https://your-identity-server")
result = client.resolve_identity("did:web:example.com:agents:agent-1")
```

## Supported DID Methods

| Method    | Description                                      |
|-----------|--------------------------------------------------|
| `did:key` | Self-contained; public key encodes the DID       |
| `did:web` | Hosted DID document at a well-known HTTPS URL    |

## FIRE LINE

See [FIRE_LINE.md](./FIRE_LINE.md) for the explicit boundary between this project and trust-scoring or governance systems.

## License

Business Source License 1.1 — see [LICENSE](./LICENSE).

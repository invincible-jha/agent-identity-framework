# CLAUDE.md — agent-identity-framework

## Project Context

Phase 4, Project 4.4 of the AumOS open-source ecosystem.
SPIFFE/DID-compatible identity issuance and verification for AI agents.

## Language Versions

- Go 1.22+ — module path `github.com/aumos-ai/agent-identity-framework`
- TypeScript 5.4+ strict mode — package `@aumos/agent-identity`
- Python 3.10+ with full type hints — package `aumos-agent-identity`

## License Header (Required on Every Source File)

Go / TypeScript:
```
// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation
```

Python:
```
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
```

## Fire Line

Read FIRE_LINE.md before adding any new type or method. The forbidden identifier list is enforced by `scripts/fire-line-audit.sh`.

## Package Responsibilities

| Package         | Responsibility                                              |
|-----------------|-------------------------------------------------------------|
| `identity`      | AgentIdentity struct, IdentityManager, VC issuance          |
| `spiffe`        | Workload identity adapter, SVID handling                    |
| `keys`          | KeyManager interface, Ed25519 impl, rotation                |
| `types`         | Shared value types and custom error types                   |

## DID Method Constraints

Only `did:web` and `did:key` are permitted.
`did:key` encoding: multibase base58btc of the raw Ed25519 public key with the `0xed01` multicodec prefix.

## Credential Constraints

Use only generic W3C VC schemas.
The `type` array must contain `"VerifiableCredential"` as the first element.
No AumOS-specific credential schemas.

## Key Storage

The `KeyManager` interface is pluggable.
The shipped implementations are:
- `InMemoryKeyStore` — for testing and short-lived agents
- `FileKeyStore` — persists keys to an encrypted JSON file on disk

No TEE or HSM backends ship with this package.

## Concurrency

All exported methods on `IdentityManager` must be safe for concurrent use.
Use `sync.RWMutex` where shared state is involved.
Prefer returning errors over panicking.

## Naming Conventions

- Acronyms uppercase: `DID`, `VC`, `SPIFFE`, `SVID`, `JWT`, `x509`
- Context as first argument on all exported methods
- Constructor pattern: `NewXxx(opts) (*Xxx, error)`

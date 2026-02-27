<!-- SPDX-License-Identifier: BSL-1.1 -->
<!-- Copyright (c) 2026 MuVeraAI Corporation -->

# Zero-Trust Architecture for AI Agents

## Principle: Never Trust, Always Verify

Traditional software systems often operate under an implicit trust model where
internal services are assumed safe once they pass perimeter security. This
assumption is fundamentally incompatible with AI agents, which are autonomous
software entities capable of taking actions with real-world consequences.

AumOS applies zero-trust principles to every agent interaction:

- **No implicit trust.** Every agent request is independently verified,
  regardless of network location or prior interactions.
- **Static trust assignment.** Trust levels are assigned by human operators
  and stored in operator configuration. Trust is never earned, computed, or
  inferred from agent behavior.
- **Least privilege by default.** New agents start at the lowest trust level
  (L0 Observer) and can only be promoted through explicit operator action.
- **Continuous verification.** Identity and authorization are checked on
  every request, not just at session establishment.

## Agent Identity Verification Flow

Agent identity in AumOS follows a three-layer verification chain:

```
SPIFFE (Workload Identity)
        |
        v
OAuth 2.1 (Client Authentication)
        |
        v
Cryptographic Attestation (Claim Verification)
```

### Layer 1: SPIFFE Workload Identity

Every agent workload receives a SPIFFE Verifiable Identity Document (SVID)
from the platform's SPIRE server. The SPIFFE ID takes the form:

```
spiffe://<trust-domain>/agents/<agent-id>
```

The SVID provides:
- Workload-level identity bound to the runtime environment
- Automatic certificate rotation via the SPIFFE Workload API
- Trust domain isolation between organizational boundaries

### Layer 2: OAuth 2.1 Client Authentication

Agents authenticate to the governance engine using OAuth 2.1 with the
`private_key_jwt` client authentication method. The flow:

1. Agent receives ECDSA P-256 credentials from the CredentialManager.
2. Agent creates a signed JWT client assertion.
3. Agent presents the assertion to the OAuth 2.1 token endpoint.
4. The governance engine validates the assertion signature and issues
   a scoped access token.

Credential rotation is operator-triggered only. There is no automatic
credential renewal or rotation based on usage patterns.

### Layer 3: Cryptographic Attestation

Attestation claims provide verifiable assertions about an agent's identity,
capabilities, trust level, and origin. Each claim is individually signed
by an Attestor using ECDSA P-256.

Attestation bundles group multiple claims for atomic verification:
either all claims verify successfully, or the entire bundle is rejected.

Supported claim types:
- `IDENTITY` -- the agent is who it claims to be
- `CAPABILITY` -- the agent possesses a specific capability
- `TRUST_LEVEL` -- the static trust level assigned by an operator
- `ORIGIN` -- the deployment environment or organization of the agent

## Trust Level Architecture

AumOS defines six trust levels, each strictly superseding the one below it:

| Level | Name              | Permissions                              |
|-------|-------------------|------------------------------------------|
| L0    | Observer          | Read-only observation, no side effects   |
| L1    | Monitor           | Active monitoring with alerting          |
| L2    | Suggest           | Generate proposals requiring human review|
| L3    | Act-with-Approval | Act only with explicit human approval    |
| L4    | Act-and-Report    | Act autonomously, report post-hoc        |
| L5    | Autonomous        | Fully autonomous within defined scope    |

Trust levels are:
- **Assigned manually** by human operators via the TrustManager API
- **Scoped** to specific domains (e.g., "production", "staging")
- **Expirable** with optional TTL set at assignment time
- **Audited** with every assignment recorded in the audit trail

## Mutual TLS Between Agent and Governance Engine

All communication between agents and the governance engine is secured with
mutual TLS (mTLS). Both parties present x509 certificates:

```
+------------------+         mTLS          +---------------------+
|                  |  <------------------> |                     |
|   Agent          |   SVID (client cert)  |  Governance Engine  |
|   (SPIFFE SVID)  |   Engine cert (server)|  (SPIFFE SVID)      |
|                  |  <------------------> |                     |
+------------------+                       +---------------------+
        |                                          |
        v                                          v
   SPIRE Agent                               SPIRE Agent
   (trust domain A)                          (trust domain A)
```

The mTLS handshake verifies:
1. The agent's SVID is issued by a trusted SPIRE server.
2. The governance engine's certificate is issued by the same trust domain.
3. Both certificates are within their validity period.
4. Neither certificate has been revoked.

## Complete Verification Flow

The full verification flow for an agent making a governed request:

```
Agent                    Governance Engine              Trust Store
  |                           |                            |
  |--- mTLS handshake ------->|                            |
  |    (present SVID)         |                            |
  |<-- mTLS accepted ---------|                            |
  |                           |                            |
  |--- OAuth 2.1 token req -->|                            |
  |    (private_key_jwt)      |                            |
  |<-- access token ----------|                            |
  |                           |                            |
  |--- governed request ----->|                            |
  |    (Bearer token +        |--- lookup trust level ---->|
  |     attestation bundle)   |<-- static trust level -----|
  |                           |                            |
  |                           |--- evaluate governance --->|
  |                           |    (trust + budget +       |
  |                           |     consent checks)        |
  |                           |                            |
  |                           |--- record audit entry ---->|
  |                           |                            |
  |<-- allow/deny response ---|                            |
  |                           |                            |
```

## Key Design Decisions

**Why static trust instead of dynamic scoring?**
Dynamic trust scoring creates an opaque system where agents can game their
way to higher privileges. Static trust ensures that every privilege escalation
is a deliberate human decision with a clear audit trail.

**Why three identity layers?**
Each layer addresses a different threat model:
- SPIFFE: workload identity in dynamic infrastructure
- OAuth 2.1: application-level authentication and scoping
- Attestation: verifiable claims that can be checked offline

**Why all-or-nothing bundle verification?**
Partial verification of attestation bundles would allow an attacker to
present a bundle with some valid and some forged claims. All-or-nothing
verification ensures the bundle is treated as a single unit of trust.

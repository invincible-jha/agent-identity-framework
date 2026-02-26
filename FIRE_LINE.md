# FIRE LINE — agent-identity-framework

This document defines the hard boundary between `agent-identity-framework` and adjacent systems. Any contribution that crosses this line will be rejected regardless of technical merit.

## What This Project IS

- Cryptographic identity issuance and verification for AI agents
- DID document generation and resolution (`did:web`, `did:key` only)
- SPIFFE workload identity adapter and SVID handling
- Ed25519 key management with a pluggable storage interface
- W3C Verifiable Credential issuance and verification (generic schemas only)

## What This Project IS NOT

### Forbidden Types and Methods

The following identifiers MUST NOT appear anywhere in this codebase:

- `TrustAttestation` — belongs to the Trust Ladder system, not identity
- `TrustBundle` — same as above
- `BehavioralBiometric` — out of scope; identity does not profile behavior
- `SocialIdentity` — identity is cryptographic, not social-graph-based
- `LegalIdentity` — jurisdiction-aware legal binding is out of scope
- `HumanAgentBinding` — binding agents to humans is a governance concern, not identity
- `progressLevel`, `promoteLevel`, `computeTrustScore`, `behavioralScore` — trust-scoring primitives
- `adaptiveBudget`, `optimizeBudget`, `predictSpending` — resource governance primitives
- `detectAnomaly`, `generateCounterfactual` — behavioral analysis primitives
- `PersonalWorldModel`, `MissionAlignment`, `SocialTrust` — cognitive agent model primitives
- `CognitiveLoop`, `AttentionFilter` — agent architecture primitives
- `GOVERNANCE_PIPELINE` — governance orchestration primitive

### Forbidden Integrations

- **Trust Ladder** — identity MUST NOT read or write trust levels; it issues proofs, not scores
- **Persona or communication style configuration** — this package has no concept of personality
- **Jurisdiction-aware disclosure generation** — legal compliance is out of scope
- **CRDT-based multi-device sync** — identity storage is append-only with rotation; no CRDT
- **did:aumos** — only `did:web` and `did:key` are supported DID methods
- **AumOS-specific credential schemas** — credentials follow generic W3C VC schemas only
- **TEE/HSM key backends** — the shipped backend is software-only; hardware attestation is a separate package

## Why This Boundary Exists

Trust scoring, governance, and behavioral analysis require access to runtime behavior signals. Identity is a *precondition* for those systems — it provides the cryptographic root of who an agent is, not what level of trust it has earned. Mixing the two creates circular dependencies and makes both systems harder to audit.

Identity must remain a narrow, auditable primitive that can be verified without any runtime state.

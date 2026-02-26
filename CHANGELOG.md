# Changelog

All notable changes to `agent-identity-framework` will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Go core library: `AgentIdentity`, `IdentityManager`, DID document generation (`did:web`, `did:key`)
- DID resolver with HTTP fetch for `did:web` and multibase decode for `did:key`
- W3C Verifiable Credential issuance and Ed25519 signature verification
- SPIFFE workload identity adapter and SVID handler (x509 + JWT)
- Ed25519 key manager with in-memory and file-system storage backends
- Key rotation with identity continuity preservation
- TypeScript client SDK (`@aumos/agent-identity`) — DID resolution, VC verification
- Python client SDK (`aumos-agent-identity`) — DID resolution, VC verification
- Example programs: basic identity, SPIFFE integration, DID resolution
- Architecture and integration documentation

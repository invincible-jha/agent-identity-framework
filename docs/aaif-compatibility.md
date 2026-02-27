<!-- SPDX-License-Identifier: BSL-1.1 -->
<!-- Copyright (c) 2026 MuVeraAI Corporation -->

# AAIF Compatibility Guide

## Overview

The Agent Authentication and Identity Framework (AAIF) defines a standard
for authenticating and identifying AI agents across platforms. This document
describes how AumOS agent identity maps to AAIF concepts and provides
guidance for organizations operating in both ecosystems.

## Concept Mapping

| AAIF Concept              | AumOS Equivalent                          |
|---------------------------|-------------------------------------------|
| Agent Identifier          | Agent DID (did:key or did:web)            |
| Agent Credential          | Verifiable Credential (W3C VC)            |
| Authentication Token      | OAuth 2.1 access token (private_key_jwt)  |
| Identity Provider         | SPIRE server + IdentityManager            |
| Capability Declaration    | Attestation claim (CAPABILITY type)       |
| Trust Score               | Static trust level (L0-L5, operator-set)  |
| Agent Profile             | AgentIdentity struct + attestation bundle |

## SPIFFE Identity Interoperability

AumOS agents receive SPIFFE IDs of the form:

```
spiffe://<trust-domain>/agents/<agent-id>
```

AAIF agent identifiers typically follow a URI pattern:

```
aaif:agent:<organization>:<agent-name>
```

The WorkloadIdentityAdapter maps between these formats by deriving a
did:web DID from the SPIFFE ID. Organizations can maintain a bidirectional
mapping table:

| SPIFFE ID                                    | AAIF Identifier              | AumOS DID                          |
|----------------------------------------------|------------------------------|------------------------------------|
| spiffe://example.com/agents/assistant-1      | aaif:agent:example:assistant  | did:web:example.com:agents:assist-1|
| spiffe://example.com/agents/data-processor   | aaif:agent:example:processor  | did:web:example.com:agents:proc-1  |

## Trust Level Translation

AumOS uses a six-level static trust hierarchy. AAIF defines access tiers
that can be mapped as follows:

| AumOS Trust Level | AumOS Name          | AAIF Access Tier     | Permissions Summary           |
|-------------------|---------------------|----------------------|-------------------------------|
| L0                | Observer            | Read-Only            | No mutations, observation only|
| L1                | Monitor             | Monitor              | Alerting, no mutations        |
| L2                | Suggest             | Contributor          | Proposals require review      |
| L3                | Act-with-Approval   | Restricted Actor     | Actions need human approval   |
| L4                | Act-and-Report      | Autonomous Actor     | Act freely, report post-hoc   |
| L5                | Autonomous          | Full Access          | Unrestricted within scope     |

Important differences:
- AumOS trust levels are **static** and **operator-assigned**. They do not
  change based on agent behavior or usage patterns.
- AAIF access tiers may incorporate dynamic risk signals in some
  implementations. When bridging, always use the AumOS static level as the
  authoritative source and treat AAIF tier mapping as a translation layer.
- Trust level scoping differs: AumOS levels are scoped to named domains
  (e.g., "production"), while AAIF tiers may be scoped to resource groups.

## Credential Exchange

Organizations using both AumOS and AAIF can exchange credentials by:

1. **Issuing a Verifiable Credential** via AumOS CredentialIssuer that
   includes AAIF-compatible claims in the credentialSubject.

2. **Including the AAIF agent identifier** as an additional claim in the
   VC's credentialSubject field alongside the AumOS agent DID.

3. **Presenting the VC** to AAIF-aware systems, which can verify the
   Ed25519 signature and extract both identifiers.

Example credentialSubject for a dual-identity credential:

```json
{
  "id": "did:web:example.com:agents:assistant-1",
  "aaifIdentifier": "aaif:agent:example:assistant",
  "trustLevel": "L2",
  "capabilities": ["text-generation", "summarization"]
}
```

## Migration Guide

### From AAIF to AumOS

1. **Map agent identifiers.** For each AAIF agent identifier, create a
   corresponding AumOS AgentIdentity using IdentityManager.CreateIdentity.
   Store the AAIF identifier in a mapping table for cross-reference.

2. **Translate access tiers.** Map each AAIF access tier to the
   corresponding AumOS trust level using the table above. Assign the trust
   level via TrustManager.SetLevel. All assignments are manual and audited.

3. **Issue SPIFFE identities.** Register each agent workload with SPIRE to
   receive a SPIFFE SVID. Use WorkloadIdentityAdapter to link the SPIFFE
   identity to the AumOS AgentIdentity.

4. **Re-issue credentials.** Replace AAIF authentication tokens with AumOS
   OAuth 2.1 credentials via CredentialManager.IssueCredentials. The
   private_key_jwt method provides equivalent security to AAIF's token-based
   authentication.

5. **Create attestation claims.** For each AAIF capability declaration,
   create an AumOS attestation claim of type CAPABILITY via Attestor.CreateClaim.

### From AumOS to AAIF

1. **Export agent DIDs.** For each AumOS AgentIdentity, derive the
   corresponding AAIF agent identifier using your organization's naming
   convention.

2. **Map trust levels.** Translate AumOS static trust levels to AAIF
   access tiers using the mapping table. Note that AAIF systems expecting
   dynamic trust signals will need an adapter that presents the static
   AumOS level as a fixed signal.

3. **Bridge credentials.** Issue AAIF-compatible credentials that embed
   the AumOS agent DID as an additional claim for traceability.

## Limitations

- AumOS does not implement dynamic trust scoring. AAIF systems that rely
  on behavioral trust signals will receive a static trust value from AumOS.
- AAIF agent profiles may contain fields that have no AumOS equivalent.
  These fields should be preserved in a metadata map during migration.
- The SPIFFE-to-AAIF identifier mapping requires a persistent index that
  is maintained by the deploying organization.

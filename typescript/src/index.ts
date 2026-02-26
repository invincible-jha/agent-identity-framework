// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @aumos/agent-identity
 *
 * SPIFFE/DID-compatible identity verification client for AI agents.
 *
 * @example
 * ```typescript
 * import { IdentityClient, verifyCredential } from "@aumos/agent-identity";
 *
 * // Use the client against a running identity server
 * const client = new IdentityClient({ baseURL: "https://identity.example.com" });
 * const identity = await client.resolveIdentity("did:key:z6Mk...");
 *
 * // Or verify credentials directly (no server required for did:key)
 * const result = await verifyCredential(vc);
 * ```
 */

export { IdentityClient } from "./client.js";
export { verifyCredential } from "./verification.js";
export type { VerifierOptions } from "./verification.js";

export {
  deriveKeyDID,
  extractPublicKeyFromKeyDID,
  extractPublicKeyFromDocument,
  parseDIDMethod,
  webDIDToURL,
  encodeBase58Btc,
  decodeBase58Btc,
  validateDIDDocument,
} from "./did.js";

export {
  canonicalizeCredential,
  checkCredentialExpiry,
  decodeProofValue,
  extractSubjectID,
  validateCredentialStructure,
} from "./credential.js";

export type {
  AgentIdentity,
  DIDDocument,
  DIDMethod,
  IdentityClientOptions,
  IdentityStatus,
  KeyAlgorithm,
  ProofType,
  VerifiableCredential,
  VerificationMethod,
  VerificationMethodType,
  VerificationResult,
  CredentialProof,
} from "./types.js";

export { IdentityClientError } from "./types.js";

// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * Supported DID methods. Only did:web and did:key are implemented.
 */
export type DIDMethod = "web" | "key";

/**
 * Lifecycle status of an agent identity.
 */
export type IdentityStatus = "active" | "expired" | "revoked";

/**
 * Cryptographic algorithm used by a key pair.
 */
export type KeyAlgorithm = "Ed25519";

/**
 * W3C Verifiable Credential type for an agent.
 */
export type VerificationMethodType = "Ed25519VerificationKey2020";

/**
 * Proof type for a Linked Data Proof attached to a Verifiable Credential.
 */
export type ProofType = "Ed25519Signature2020";

/**
 * AgentIdentity is the canonical representation of a verified AI agent identity.
 */
export interface AgentIdentity {
  /** Decentralized Identifier for this agent. */
  readonly did: string;
  /** DID of the owner who created this agent identity. */
  readonly ownerDid: string;
  /** Base64url-encoded Ed25519 public key bytes. */
  readonly publicKeyBase64: string;
  /** ISO-8601 creation timestamp. */
  readonly createdAt: string;
  /** ISO-8601 expiry timestamp. */
  readonly expiresAt: string;
  /** Lifecycle status. */
  readonly status: IdentityStatus;
}

/**
 * A verification method entry within a DID Document.
 */
export interface VerificationMethod {
  readonly id: string;
  readonly type: VerificationMethodType;
  readonly controller: string;
  readonly publicKeyMultibase: string;
}

/**
 * W3C DID Document.
 */
export interface DIDDocument {
  readonly "@context": ReadonlyArray<string>;
  readonly id: string;
  readonly verificationMethod: ReadonlyArray<VerificationMethod>;
  readonly authentication: ReadonlyArray<string>;
  readonly assertionMethod: ReadonlyArray<string>;
  readonly created?: string;
  readonly updated?: string;
}

/**
 * Linked Data Proof attached to a Verifiable Credential.
 */
export interface CredentialProof {
  readonly type: ProofType;
  readonly created: string;
  readonly verificationMethod: string;
  readonly proofPurpose: string;
  /** Base64url-encoded Ed25519 signature. */
  readonly proofValue: string;
}

/**
 * W3C Verifiable Credential (generic schema only).
 */
export interface VerifiableCredential {
  readonly "@context": ReadonlyArray<string>;
  readonly id: string;
  readonly type: ReadonlyArray<string>;
  readonly issuer: string;
  readonly issuanceDate: string;
  readonly expirationDate?: string;
  readonly credentialSubject: Readonly<Record<string, unknown>>;
  readonly proof?: CredentialProof;
}

/**
 * Result returned by verifyCredential.
 */
export interface VerificationResult {
  readonly valid: boolean;
  readonly issuerDid: string;
  readonly subjectId?: string;
  readonly credentialId: string;
  readonly expiresAt?: Date;
  /** Populated when valid is false. */
  readonly reason?: string;
}

/**
 * Options for constructing an IdentityClient.
 */
export interface IdentityClientOptions {
  /** Base URL of the identity server (e.g. "https://identity.example.com"). */
  readonly baseURL: string;
  /**
   * Optional custom fetch implementation. Defaults to the global fetch.
   * Useful for injecting authentication headers or mocking in tests.
   */
  readonly fetch?: typeof globalThis.fetch;
  /** Request timeout in milliseconds. Defaults to 10000 (10s). */
  readonly timeoutMs?: number;
}

/**
 * IdentityClientError is thrown when the identity server returns a non-2xx response.
 */
export class IdentityClientError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly endpoint: string,
    message: string,
  ) {
    super(`IdentityClient [${statusCode}] ${endpoint}: ${message}`);
    this.name = "IdentityClientError";
  }
}

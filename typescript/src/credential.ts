// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

import type { CredentialProof, VerifiableCredential } from "./types.js";

/**
 * Returns the canonical JSON bytes of a VerifiableCredential without its proof.
 * This is the byte sequence that was signed and must be re-created for verification.
 */
export function canonicalizeCredential(vc: VerifiableCredential): Uint8Array {
  const withoutProof: Omit<VerifiableCredential, "proof"> = {
    "@context": vc["@context"],
    id: vc.id,
    type: vc.type,
    issuer: vc.issuer,
    issuanceDate: vc.issuanceDate,
    ...(vc.expirationDate !== undefined
      ? { expirationDate: vc.expirationDate }
      : {}),
    credentialSubject: vc.credentialSubject,
  };
  const json = JSON.stringify(withoutProof);
  return new TextEncoder().encode(json);
}

/**
 * Decodes the base64url ProofValue from a CredentialProof into raw bytes.
 */
export function decodeProofValue(proof: CredentialProof): Uint8Array {
  const padded = addBase64Padding(proof.proofValue);
  return base64UrlDecode(padded);
}

/**
 * Validates that a VerifiableCredential has the basic required structure.
 */
export function validateCredentialStructure(vc: unknown): vc is VerifiableCredential {
  if (typeof vc !== "object" || vc === null) return false;
  const c = vc as Record<string, unknown>;
  if (!Array.isArray(c["type"])) return false;
  if (!(c["type"] as string[]).includes("VerifiableCredential")) return false;
  if (typeof c["issuer"] !== "string") return false;
  if (typeof c["issuanceDate"] !== "string") return false;
  if (typeof c["credentialSubject"] !== "object") return false;
  return true;
}

/**
 * Checks whether a VerifiableCredential has expired.
 * Returns the parsed expiry Date, or undefined if no expiry is set.
 */
export function checkCredentialExpiry(vc: VerifiableCredential): {
  expired: boolean;
  expiresAt?: Date;
} {
  if (!vc.expirationDate) return { expired: false };
  const expiresAt = new Date(vc.expirationDate);
  return { expired: Date.now() > expiresAt.getTime(), expiresAt };
}

/**
 * Extracts the subject ID from a credential's credentialSubject.
 */
export function extractSubjectID(
  credentialSubject: Readonly<Record<string, unknown>>,
): string | undefined {
  const id = credentialSubject["id"];
  return typeof id === "string" ? id : undefined;
}

// --- Internal base64url utilities (no external dependency) ---

function addBase64Padding(s: string): string {
  const remainder = s.length % 4;
  if (remainder === 2) return s + "==";
  if (remainder === 3) return s + "=";
  return s;
}

function base64UrlDecode(s: string): Uint8Array {
  const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

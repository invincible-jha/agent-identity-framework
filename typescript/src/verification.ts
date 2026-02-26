// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

import { ed25519 } from "@noble/ed25519";

import {
  canonicalizeCredential,
  checkCredentialExpiry,
  decodeProofValue,
  extractSubjectID,
} from "./credential.js";
import {
  extractPublicKeyFromDocument,
  extractPublicKeyFromKeyDID,
  parseDIDMethod,
  webDIDToURL,
  validateDIDDocument,
} from "./did.js";
import type {
  DIDDocument,
  VerifiableCredential,
  VerificationResult,
} from "./types.js";

/**
 * VerifierOptions controls how credential verification is performed.
 */
export interface VerifierOptions {
  /**
   * Custom fetch implementation. Defaults to globalThis.fetch.
   * Required for did:web resolution (did:key is resolved locally).
   */
  readonly fetch?: typeof globalThis.fetch;
  /** Timeout in milliseconds for did:web HTTP fetches. Defaults to 10000. */
  readonly timeoutMs?: number;
}

/**
 * verifyCredential resolves the issuer DID, extracts the Ed25519 public key,
 * and verifies the credential's Ed25519 proof.
 *
 * For did:key issuers, resolution is entirely local (no network call).
 * For did:web issuers, the DID document is fetched via HTTPS.
 */
export async function verifyCredential(
  vc: VerifiableCredential,
  options: VerifierOptions = {},
): Promise<VerificationResult> {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;

  const failure = (reason: string): VerificationResult => ({
    valid: false,
    issuerDid: vc.issuer,
    credentialId: vc.id,
    reason,
  });

  if (!vc.proof) {
    return failure("credential has no proof");
  }
  if (vc.proof.type !== "Ed25519Signature2020") {
    return failure(`unsupported proof type: ${vc.proof.type}`);
  }

  const { expired, expiresAt } = checkCredentialExpiry(vc);
  if (expired) {
    return {
      valid: false,
      issuerDid: vc.issuer,
      credentialId: vc.id,
      expiresAt,
      reason: "credential has expired",
    };
  }

  // Resolve the issuer's DID document.
  let doc: DIDDocument;
  try {
    doc = await resolveDIDDocument(vc.issuer, fetchImpl, timeoutMs);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return failure(`DID resolution failed: ${message}`);
  }

  // Extract the public key from the document.
  let publicKey: Uint8Array;
  try {
    publicKey = extractPublicKeyFromDocument(doc);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return failure(`extract public key: ${message}`);
  }

  // Decode the signature from the proof.
  let signature: Uint8Array;
  try {
    signature = decodeProofValue(vc.proof);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return failure(`decode proof value: ${message}`);
  }

  if (signature.length !== 64) {
    return failure(`unexpected signature length: ${signature.length}`);
  }

  // Canonicalize the credential (without proof) and verify the signature.
  const canonical = canonicalizeCredential(vc);
  const isValid = await ed25519.verify(signature, canonical, publicKey);
  if (!isValid) {
    return failure("Ed25519 signature is invalid");
  }

  const subjectId = extractSubjectID(vc.credentialSubject);

  return {
    valid: true,
    issuerDid: vc.issuer,
    subjectId,
    credentialId: vc.id,
    expiresAt,
  };
}

/**
 * Resolves a DID document for either did:key or did:web.
 */
async function resolveDIDDocument(
  did: string,
  fetchImpl: typeof globalThis.fetch,
  timeoutMs: number,
): Promise<DIDDocument> {
  const method = parseDIDMethod(did);

  if (method === "key") {
    // did:key resolution is entirely local — extract the key and build the document.
    const publicKey = extractPublicKeyFromKeyDID(did);
    return buildKeyDIDDocument(did, publicKey);
  }

  // did:web: fetch the document from the well-known URL.
  const url = webDIDToURL(did);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetchImpl(url, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} from ${url}`);
  }

  const raw: unknown = await response.json();
  return validateDIDDocument(raw, did);
}

/**
 * Synthesizes a DID document from a did:key public key.
 * No network call is required.
 */
function buildKeyDIDDocument(did: string, publicKey: Uint8Array): DIDDocument {
  // Encode as multibase base58btc (prefix 'z') for the publicKeyMultibase field.
  // Import inline to avoid circular dependency with did.ts's encodeBase58Btc.
  const encoded = "z" + base58BtcEncode(publicKey);
  const vmID = `${did}#key-1`;

  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: vmID,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: encoded,
      },
    ],
    authentication: [vmID],
    assertionMethod: [vmID],
  };
}

// Minimal base58btc encoder used inline to avoid circular imports.
const BASE58_CHARS =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58BtcEncode(bytes: Uint8Array): string {
  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += (digits[i] ?? 0) << 8;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let result = "";
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_CHARS[digits[i] ?? 0];
  }
  return result;
}

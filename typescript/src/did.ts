// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

import type { DIDDocument, DIDMethod, VerificationMethod } from "./types.js";

/**
 * Multicodec prefix for Ed25519 public keys: 0xed 0x01.
 * Used in did:key encoding per the multicodec specification.
 */
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

/**
 * Base58btc alphabet (Bitcoin alphabet, used by did:key).
 */
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encodes a Uint8Array to base58btc (Bitcoin encoding).
 */
export function encodeBase58Btc(bytes: Uint8Array): string {
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
  for (const byte of bytes) {
    if (byte !== 0) break;
    result += "1";
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i] ?? 0];
  }
  return result;
}

/**
 * Decodes a base58btc string to Uint8Array.
 */
export function decodeBase58Btc(encoded: string): Uint8Array {
  const bytes: number[] = [0];
  for (const char of encoded) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value < 0) throw new Error(`Invalid base58btc character: ${char}`);
    let carry = value;
    for (let i = 0; i < bytes.length; i++) {
      carry += (bytes[i] ?? 0) * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  let leadingZeros = 0;
  for (const char of encoded) {
    if (char !== "1") break;
    leadingZeros++;
  }

  const result = new Uint8Array(leadingZeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    result[leadingZeros + i] = bytes[bytes.length - 1 - i] ?? 0;
  }
  return result;
}

/**
 * Derives a did:key DID from a raw Ed25519 public key (32 bytes).
 * Encoding: multibase base58btc prefix 'z' + base58btc(0xed01 || publicKeyBytes).
 */
export function deriveKeyDID(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(
      `deriveKeyDID: expected 32-byte Ed25519 public key, got ${publicKey.length}`,
    );
  }
  const prefixed = new Uint8Array(
    ED25519_MULTICODEC_PREFIX.length + publicKey.length,
  );
  prefixed.set(ED25519_MULTICODEC_PREFIX);
  prefixed.set(publicKey, ED25519_MULTICODEC_PREFIX.length);
  return "did:key:z" + encodeBase58Btc(prefixed);
}

/**
 * Extracts the raw Ed25519 public key bytes from a did:key DID.
 */
export function extractPublicKeyFromKeyDID(did: string): Uint8Array {
  if (!did.startsWith("did:key:z")) {
    throw new Error(`extractPublicKeyFromKeyDID: not a base58btc did:key: ${did}`);
  }
  const encoded = did.slice("did:key:z".length);
  const decoded = decodeBase58Btc(encoded);

  if (decoded.length < ED25519_MULTICODEC_PREFIX.length) {
    throw new Error("extractPublicKeyFromKeyDID: decoded bytes too short");
  }
  if (
    decoded[0] !== ED25519_MULTICODEC_PREFIX[0] ||
    decoded[1] !== ED25519_MULTICODEC_PREFIX[1]
  ) {
    throw new Error(
      "extractPublicKeyFromKeyDID: unexpected multicodec prefix",
    );
  }

  const rawKey = decoded.slice(ED25519_MULTICODEC_PREFIX.length);
  if (rawKey.length !== 32) {
    throw new Error(
      `extractPublicKeyFromKeyDID: expected 32 key bytes, got ${rawKey.length}`,
    );
  }
  return rawKey;
}

/**
 * Parses the DID method from a DID string.
 * Only "key" and "web" are supported.
 */
export function parseDIDMethod(did: string): DIDMethod {
  const parts = did.split(":");
  if (parts.length < 3 || parts[0] !== "did") {
    throw new Error(`parseDIDMethod: invalid DID format: ${did}`);
  }
  const method = parts[1];
  if (method !== "web" && method !== "key") {
    throw new Error(`parseDIDMethod: unsupported DID method "${method}"`);
  }
  return method;
}

/**
 * Converts a did:web DID to the canonical HTTPS URL for its DID document.
 *
 * did:web:example.com             => https://example.com/.well-known/did.json
 * did:web:example.com:agents:abc  => https://example.com/agents/abc/did.json
 */
export function webDIDToURL(did: string): string {
  const withoutScheme = did.slice("did:web:".length);
  if (!withoutScheme) {
    throw new Error(`webDIDToURL: empty did:web host in: ${did}`);
  }

  const colonIndex = withoutScheme.indexOf(":");
  if (colonIndex < 0) {
    const host = withoutScheme.replace(/%3A/gi, ":");
    return `https://${host}/.well-known/did.json`;
  }

  const host = withoutScheme.slice(0, colonIndex).replace(/%3A/gi, ":");
  const pathPart = withoutScheme.slice(colonIndex + 1).replaceAll(":", "/");
  return `https://${host}/${pathPart}/did.json`;
}

/**
 * Extracts the first Ed25519 public key from a DID document's verificationMethod array.
 * Returns the raw 32-byte key as a Uint8Array.
 */
export function extractPublicKeyFromDocument(doc: DIDDocument): Uint8Array {
  for (const vm of doc.verificationMethod) {
    if (vm.type !== "Ed25519VerificationKey2020") continue;
    if (!vm.publicKeyMultibase.startsWith("z")) {
      throw new Error(
        `extractPublicKeyFromDocument: expected base58btc multibase (prefix 'z'), got ${vm.publicKeyMultibase[0]}`,
      );
    }
    const decoded = decodeBase58Btc(vm.publicKeyMultibase.slice(1));
    if (decoded.length !== 32) {
      throw new Error(
        `extractPublicKeyFromDocument: unexpected key length ${decoded.length}`,
      );
    }
    return decoded;
  }
  throw new Error(
    `extractPublicKeyFromDocument: no Ed25519VerificationKey2020 in document for ${doc.id}`,
  );
}

/**
 * Validates that a parsed DIDDocument has the required structure.
 */
export function validateDIDDocument(
  raw: unknown,
  expectedDID: string,
): DIDDocument {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("validateDIDDocument: response is not an object");
  }
  const doc = raw as Record<string, unknown>;

  if (doc["id"] !== expectedDID) {
    throw new Error(
      `validateDIDDocument: document id "${String(doc["id"])}" does not match requested DID "${expectedDID}"`,
    );
  }
  if (!Array.isArray(doc["verificationMethod"])) {
    throw new Error(
      "validateDIDDocument: verificationMethod is missing or not an array",
    );
  }

  return raw as DIDDocument;
}

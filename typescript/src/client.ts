// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

import { verifyCredential } from "./verification.js";
import type {
  AgentIdentity,
  DIDDocument,
  IdentityClientOptions,
  VerifiableCredential,
  VerificationResult,
} from "./types.js";
import { IdentityClientError } from "./types.js";
import { validateDIDDocument } from "./did.js";

/**
 * IdentityClient is the primary entry point for TypeScript applications that need
 * to resolve agent identities and verify Verifiable Credentials against a running
 * agent-identity-framework server.
 *
 * For did:key resolution and credential verification without a server, use
 * verifyCredential() and the did.ts utilities directly.
 */
export class IdentityClient {
  private readonly baseURL: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly timeoutMs: number;

  constructor(options: IdentityClientOptions) {
    this.baseURL = options.baseURL.replace(/\/$/, "");
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  /**
   * Resolves an AgentIdentity record by DID from the identity server.
   * This calls the server's REST API — it is distinct from DID document resolution.
   */
  async resolveIdentity(did: string): Promise<AgentIdentity> {
    const url = `${this.baseURL}/v1/identities/${encodeURIComponent(did)}`;
    const response = await this.fetch(url);
    const body: unknown = await response.json();
    return this.parseAgentIdentity(body, did);
  }

  /**
   * Resolves a DID document from the identity server's DID resolution endpoint.
   * For did:key DIDs, prefer using the local did.ts utilities directly.
   */
  async resolveDIDDocument(did: string): Promise<DIDDocument> {
    const url = `${this.baseURL}/v1/dids/${encodeURIComponent(did)}`;
    const response = await this.fetch(url);
    const raw: unknown = await response.json();
    return validateDIDDocument(raw, did);
  }

  /**
   * Verifies a Verifiable Credential using the local verification engine.
   * DID resolution (for did:web) uses the configured fetch implementation.
   */
  async verifyCredential(vc: VerifiableCredential): Promise<VerificationResult> {
    return verifyCredential(vc, {
      fetch: this.fetchImpl,
      timeoutMs: this.timeoutMs,
    });
  }

  /**
   * Lists all agent identities registered with the identity server.
   */
  async listIdentities(): Promise<ReadonlyArray<AgentIdentity>> {
    const url = `${this.baseURL}/v1/identities`;
    const response = await this.fetch(url);
    const body: unknown = await response.json();
    if (!Array.isArray(body)) {
      throw new Error("IdentityClient.listIdentities: expected array response");
    }
    return body.map((item) => this.parseAgentIdentity(item, "unknown"));
  }

  // --- Private helpers ---

  private async fetch(url: string): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      let message = response.statusText;
      try {
        const body = await response.json() as Record<string, unknown>;
        if (typeof body["error"] === "string") {
          message = body["error"];
        }
      } catch {
        // Ignore parse errors; use status text.
      }
      throw new IdentityClientError(response.status, url, message);
    }

    return response;
  }

  private parseAgentIdentity(raw: unknown, expectedDID: string): AgentIdentity {
    if (typeof raw !== "object" || raw === null) {
      throw new Error(
        `IdentityClient: expected object for identity ${expectedDID}, got ${typeof raw}`,
      );
    }
    const obj = raw as Record<string, unknown>;

    const requiredStrings = [
      "did",
      "ownerDid",
      "publicKeyBase64",
      "createdAt",
      "expiresAt",
      "status",
    ] as const;

    for (const key of requiredStrings) {
      if (typeof obj[key] !== "string") {
        throw new Error(
          `IdentityClient: identity missing or invalid field "${key}"`,
        );
      }
    }

    return raw as AgentIdentity;
  }
}

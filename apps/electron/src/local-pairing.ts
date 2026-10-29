import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import type { VaultSessionState, LocalPairingReview, LocalPairingApproval } from "@password-manager/shared/types";
import { localIdentityCertificate } from "./local-identity.js";
import type { LocalClientRegistry } from "./local-client-registry.js";

export class LocalPairingError extends Error {
  readonly code = "LOCAL_PAIRING_UNAVAILABLE";
  constructor() { super("接続元の登録を完了できません。状態を確認し、接続リクエストを選び直してください"); this.name = "LocalPairingError"; }
}
export const LOCAL_PAIRING_LIMITS = Object.freeze({ bytes: 16384, requestLifetimeMs: 5 * 60000, reviewLifetimeMs: 60000, registrationLifetimeMs: 30 * 86400000 });
type ClientKind = "agent" | "browser";
type Request = { version: 1; requestId: string; displayName: string; kind: ClientKind; certificate: string; createdAt: number; expiresAt: number };
type Session = { requireUnlocked(sessionId?: string): string; requireGeneration(sessionId: unknown): string; subscribe(listener: (state: VaultSessionState) => void): () => void };
type Clock = () => { wall: number; monotonic: number };
export type PairingReview = LocalPairingReview;
export type PairingApproval = LocalPairingApproval;
function fail(): never { throw new LocalPairingError(); }
const uuid = (value: unknown): value is string => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const timestamp = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) > 0 && (value as number) <= 8640000000000000;
function details(value: { displayName: string; kind: ClientKind }) {
  if (typeof value.displayName !== "string" || value.displayName.length < 1 || value.displayName.length > 80 || value.displayName.trim() !== value.displayName ||
      /[\p{C}\p{Zl}\p{Zp}]/u.test(value.displayName) || !["agent", "browser"].includes(value.kind)) fail();
}
function parse(content: Buffer, now: number) {
  if (!Buffer.isBuffer(content) || content.length < 1 || content.length > LOCAL_PAIRING_LIMITS.bytes || !timestamp(now)) fail();
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(content)) as Request;
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "certificate,createdAt,displayName,expiresAt,kind,requestId,version" ||
      value.version !== 1 || !uuid(value.requestId) || !timestamp(value.createdAt) || !timestamp(value.expiresAt) || value.createdAt > now || value.expiresAt <= now ||
      value.expiresAt <= value.createdAt || value.expiresAt - value.createdAt > LOCAL_PAIRING_LIMITS.requestLifetimeMs ||
      typeof value.certificate !== "string" || value.certificate.length > 5464 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.certificate)) fail();
  details(value);
  const certificate = Buffer.from(value.certificate, "base64");
  if (certificate.toString("base64") !== value.certificate) fail();
  const parsed = localIdentityCertificate(certificate, "client", now);
  if (value.expiresAt > parsed.until) fail();
  return { value, certificate: parsed.certificate, fingerprint256: parsed.fingerprint, until: parsed.until };
}

// Public transport only: no private key, self-enrollment, operation grant or external listener.
export function encodeLocalPairingRequest(input: { displayName: string; kind: ClientKind; certificate: Buffer }, now = Date.now()): Buffer {
  try {
    details(input); if (!timestamp(now)) fail();
    const certificate = localIdentityCertificate(input.certificate, "client", now);
    const value: Request = { version: 1, requestId: randomUUID(), displayName: input.displayName, kind: input.kind, certificate: certificate.certificate.toString("base64"),
      createdAt: now, expiresAt: Math.min(now + LOCAL_PAIRING_LIMITS.requestLifetimeMs, certificate.until) };
    const content = Buffer.from(JSON.stringify(value)); parse(content, now); return content;
  } catch { throw new LocalPairingError(); }
}

// The owner supplies an already opened registry. All mutation still passes its revision/session guards.
export class LocalPairingCoordinator {
  private pending?: { review: PairingReview; certificate: Buffer; sessionId: string; deadline: number };
  private observed = { wall: 0, monotonic: 0 };
  private closed = false;
  private faulted = false;
  private readonly unsubscribe: () => void;
  constructor(private readonly registry: LocalClientRegistry, private readonly session: Session,
    private readonly clock: Clock = () => ({ wall: Date.now(), monotonic: performance.now() })) {
    this.unsubscribe = session.subscribe(state => { if (!state.isUnlocked || this.pending?.sessionId !== state.sessionId) this.pending = undefined; });
  }
  private now() {
    if (this.closed || this.faulted) fail();
    const now = this.clock();
    if (!timestamp(now.wall) || !Number.isFinite(now.monotonic) || now.monotonic < this.observed.monotonic || now.wall < this.observed.wall) {
      this.faulted = true; this.pending = undefined; fail();
    }
    this.observed = { ...now }; return now;
  }
  private unlocked(sessionId: string) { if (typeof sessionId !== "string" || this.session.requireUnlocked(sessionId) !== sessionId) fail(); }
  stage(sessionId: string, content: Buffer): PairingReview {
    this.pending = undefined;
    try {
      this.unlocked(sessionId); const now = this.now(), parsed = parse(content, now.wall), listing = this.registry.list(sessionId);
      if (listing.clients.some(client => client.fingerprint256 === parsed.fingerprint256)) fail();
      const lifetime = Math.min(LOCAL_PAIRING_LIMITS.reviewLifetimeMs, parsed.value.expiresAt - now.wall);
      const review = Object.freeze({ pendingId: randomUUID(), displayName: parsed.value.displayName, kind: parsed.value.kind,
        fingerprint256: parsed.fingerprint256, expiresAt: now.wall + lifetime,
        registrationExpiresAt: Math.min(now.wall + LOCAL_PAIRING_LIMITS.registrationLifetimeMs, parsed.until), revision: listing.revision });
      this.pending = { review, certificate: parsed.certificate, sessionId, deadline: now.monotonic + lifetime }; return review;
    } catch { throw new LocalPairingError(); }
  }
  current(sessionId: string): PairingReview | null {
    try {
      this.unlocked(sessionId); const now = this.now(), pending = this.pending;
      if (!pending) return null;
      if (pending.sessionId !== sessionId || now.wall >= pending.review.expiresAt || now.monotonic >= pending.deadline || this.registry.list(sessionId).revision !== pending.review.revision) {
        this.pending = undefined; return null;
      }
      return pending.review;
    } catch { this.pending = undefined; throw new LocalPairingError(); }
  }
  approve(sessionId: string, approval: PairingApproval) {
    try {
      if (!approval || typeof approval !== "object" || Object.keys(approval).sort().join(",") !== "confirmation,expectedRevision,fingerprint256,pendingId" ||
          approval.confirmation !== "MATCHED_FINGERPRINT") fail();
      const review = this.current(sessionId), pending = this.pending;
      if (!review || !pending || approval.pendingId !== review.pendingId || approval.expectedRevision !== review.revision || approval.fingerprint256 !== review.fingerprint256) fail();
      // Consume before touching durable state; failures never leave an approval reusable.
      this.pending = undefined;
      return this.registry.enroll(sessionId, review.revision, { displayName: review.displayName, kind: review.kind, certificate: pending.certificate, expiresAt: review.registrationExpiresAt });
    } catch { throw new LocalPairingError(); }
  }
  cancel(sessionId: string, pendingId: string) {
    try { const review = this.current(sessionId); if (review?.pendingId !== pendingId) fail(); this.pending = undefined; }
    catch { throw new LocalPairingError(); }
  }
  revoke(sessionId: string, expectedRevision: number, clientId: string | null) {
    try {
      this.now(); if (typeof sessionId !== "string" || this.session.requireGeneration(sessionId) !== sessionId) fail();
      this.pending = undefined; this.registry.revoke(expectedRevision, clientId);
    } catch { throw new LocalPairingError(); }
  }
  close() { if (this.closed) return; this.closed = true; this.pending = undefined; this.unsubscribe(); }
}

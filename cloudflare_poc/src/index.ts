import { DurableObject } from "cloudflare:workers";

const SCHEMA = "agent-controller-approval-challenge-v3";
const AUTHORITY = "broker-prod-primary";
const EPOCH = "epoch-2026-08-25-a";
const SIGNER = "human-key-poc-v3";
const PUBLIC_KEY_B64 = "0CYe5bUlZrfXnmfDt/hP3qf8HigcnUdzyqwIXYUJa7E=";

type ChallengeV3 = {
  approval_id: string;
  approval_policy_id: string;
  controller_task_id: string;
  operation_id: string;
  operation_version: string;
  provider: string;
  requested_capability: string;
  effect: string;
  repo: string;
  target_kind: string;
  target_id: string;
  expected_head_sha: string;
  challenge_nonce: string;
  signer_key_id: string;
  broker_authority_id: string;
  broker_epoch: string;
  schema_version: string;
};

type ClaimResult = {
  decision: "PASS" | "REPLAYED" | "BLOCKED";
  reason?: string;
  attempt_id?: string;
  authorization_digest?: string;
};

function b64bytes(value: string): Uint8Array {
  const raw = atob(value);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

function canonical(challenge: ChallengeV3): Uint8Array {
  const keys = Object.keys(challenge).sort();
  const ordered: Record<string, string> = {};
  for (const key of keys) {
    const value = (challenge as Record<string, unknown>)[key];
    if (typeof value !== "string" || value.length === 0) throw new Error("CHALLENGE_FIELD_INVALID");
    ordered[key] = value;
  }
  return new TextEncoder().encode(JSON.stringify(ordered) + "\n");
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifySignature(challenge: ChallengeV3, signatureB64: string): Promise<boolean> {
  try {
    if (challenge.signer_key_id !== SIGNER) return false;
    const key = await crypto.subtle.importKey("raw", b64bytes(PUBLIC_KEY_B64), "Ed25519", false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, b64bytes(signatureB64), canonical(challenge));
  } catch {
    return false;
  }
}

function validChallenge(value: unknown): value is ChallengeV3 {
  if (!value || typeof value !== "object") return false;
  const c = value as Record<string, unknown>;
  const fields = [
    "approval_id", "approval_policy_id", "controller_task_id", "operation_id", "operation_version",
    "provider", "requested_capability", "effect", "repo", "target_kind", "target_id",
    "expected_head_sha", "challenge_nonce", "signer_key_id", "broker_authority_id", "broker_epoch",
    "schema_version",
  ];
  return fields.every((k) => typeof c[k] === "string" && (c[k] as string).length > 0) &&
    Object.keys(c).length === fields.length;
}

export class BrokerDurableObject extends DurableObject {
  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env);
    ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS attempts (
        authorization_digest TEXT PRIMARY KEY,
        challenge_json TEXT NOT NULL,
        signature_b64 TEXT NOT NULL,
        signature_digest TEXT NOT NULL,
        broker_authority_id TEXT NOT NULL,
        broker_epoch TEXT NOT NULL,
        attempt_id TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL CHECK(state='CLAIMED')
      );
    `);
  }

  private async validateStored(row: Record<string, string>): Promise<boolean> {
    try {
      const challenge = JSON.parse(row.challenge_json) as unknown;
      if (!validChallenge(challenge)) return false;
      if (challenge.schema_version !== SCHEMA) return false;
      if (challenge.broker_authority_id !== AUTHORITY || challenge.broker_epoch !== EPOCH) return false;
      const authDigest = await sha256Hex(canonical(challenge));
      const sigDigest = await sha256Hex(b64bytes(row.signature_b64));
      if (authDigest !== row.authorization_digest || sigDigest !== row.signature_digest) return false;
      return await verifySignature(challenge, row.signature_b64);
    } catch {
      return false;
    }
  }

  async claim(challenge: unknown, signatureB64: string): Promise<ClaimResult> {
    if (!validChallenge(challenge) || challenge.schema_version !== SCHEMA) {
      return { decision: "BLOCKED", reason: "V3_CHALLENGE_REQUIRED" };
    }
    if (challenge.broker_authority_id !== AUTHORITY) {
      return { decision: "BLOCKED", reason: "BROKER_AUTHORITY_MISMATCH" };
    }
    if (challenge.broker_epoch !== EPOCH) {
      return { decision: "BLOCKED", reason: "BROKER_EPOCH_MISMATCH" };
    }
    if (typeof signatureB64 !== "string" || !(await verifySignature(challenge, signatureB64))) {
      return { decision: "BLOCKED", reason: "SIGNATURE_INVALID" };
    }

    const authorizationDigest = await sha256Hex(canonical(challenge));
    const signatureDigest = await sha256Hex(b64bytes(signatureB64));
    const challengeJson = new TextDecoder().decode(canonical(challenge)).trimEnd();

    const existing = this.ctx.storage.sql.exec<Record<string, string>>(
      "SELECT * FROM attempts WHERE authorization_digest = ?", authorizationDigest,
    ).toArray()[0];
    if (existing) {
      if (!(await this.validateStored(existing))) return { decision: "BLOCKED", reason: "STORED_AUTHORIZATION_INVALID" };
      return {
        decision: "REPLAYED",
        reason: "AUTHORIZATION_ALREADY_CONSUMED",
        attempt_id: existing.attempt_id,
        authorization_digest: authorizationDigest,
      };
    }

    const attemptId = `attempt_${crypto.randomUUID()}`;
    try {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(
          "INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED')",
          authorizationDigest, challengeJson, signatureB64, signatureDigest,
          challenge.broker_authority_id, challenge.broker_epoch, attemptId,
        );
      });
    } catch {
      const raced = this.ctx.storage.sql.exec<Record<string, string>>(
        "SELECT * FROM attempts WHERE authorization_digest = ?", authorizationDigest,
      ).toArray()[0];
      if (raced && await this.validateStored(raced)) {
        return { decision: "REPLAYED", reason: "AUTHORIZATION_ALREADY_CONSUMED", attempt_id: raced.attempt_id, authorization_digest: authorizationDigest };
      }
      return { decision: "BLOCKED", reason: "CLAIM_CONFLICT" };
    }

    const reread = this.ctx.storage.sql.exec<Record<string, string>>(
      "SELECT * FROM attempts WHERE authorization_digest = ?", authorizationDigest,
    ).toArray()[0];
    if (!reread || reread.attempt_id !== attemptId || !(await this.validateStored(reread))) {
      return { decision: "BLOCKED", reason: "POSTCLAIM_VERIFY_FAILED" };
    }
    return { decision: "PASS", attempt_id: attemptId, authorization_digest: authorizationDigest };
  }

  async count(): Promise<number> {
    return this.ctx.storage.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM attempts").one().n;
  }
}

interface Env {
  BROKER: DurableObjectNamespace<BrokerDurableObject>;
}

export default {
  async fetch(): Promise<Response> {
    return new Response("effect-free broker PoC", { status: 200 });
  },
} satisfies ExportedHandler<Env>;

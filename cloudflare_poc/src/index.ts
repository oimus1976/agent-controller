import { DurableObject } from "cloudflare:workers";

const CHALLENGE_SCHEMA = "agent-controller-approval-challenge-v3";
const ACTIVATION_SCHEMA = "agent-controller-broker-activation-poc-v1";
const RECOVERY_SCHEMA = "agent-controller-broker-recovery-poc-v1";
const AUTHORITY_LABEL = "agent-controller-dual-do-authority-v1";
const ADMIN_SIGNER = "human-admin-test-ephemeral";
const APPROVAL_SIGNER = "human-approval-test-ephemeral";
const LEDGER_NAME = "primary-ledger";
const WITNESS_NAME = "primary-witness";

type Decision = "PASS" | "REPLAYED" | "BLOCKED";
type ControlState = "ACTIVE" | "RECOVERY_SUSPENDED";

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

export type ActivationCertificate = {
  schema_version: string;
  activation_policy_id: string;
  activation_id: string;
  ledger_object_id: string;
  witness_object_id: string;
  broker_authority_id: string;
  broker_epoch: string;
  ledger_recovery_nonce: string;
  witness_recovery_nonce: string;
  signer_key_id: string;
};

export type RecoveryAuthorization = {
  schema_version: string;
  recovery_policy_id: string;
  recovery_id: string;
  ledger_object_id: string;
  witness_object_id: string;
  broker_authority_id: string;
  new_broker_epoch: string;
  signer_key_id: string;
};

type StoredControl = {
  state: ControlState;
  broker_authority_id: string | null;
  broker_epoch: string | null;
  pending_epoch: string | null;
  local_recovery_nonce: string;
  activation_digest: string | null;
  activation_json: string | null;
  activation_signature_b64: string | null;
};

export type BrokerStatus = {
  decision: "ACTIVE" | "RECOVERY_SUSPENDED" | "INTEGRITY_FAILED";
  broker_authority_id?: string;
  broker_epoch?: string;
  pending_epoch?: string;
  activation_digest?: string;
  local_recovery_nonce?: string;
};

type ClaimResult = {
  decision: Decision;
  reason?: string;
  attempt_id?: string;
  authorization_digest?: string;
};

type ExpectedActivation = {
  activation_digest: string;
  broker_authority_id: string;
  broker_epoch: string;
};

interface Env {
  BROKER_LEDGER: DurableObjectNamespace<BrokerLedgerDO>;
  BROKER_WITNESS: DurableObjectNamespace<BrokerWitnessDO>;
  ADMIN_PUBLIC_KEY_B64: string;
  APPROVAL_PUBLIC_KEY_B64: string;
}

function b64bytes(value: string): Uint8Array {
  const raw = atob(value);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

function bytesB64(value: Uint8Array): string {
  let out = "";
  for (const b of value) out += String.fromCharCode(b);
  return btoa(out);
}

function randomNonce(): string {
  const value = new Uint8Array(32);
  crypto.getRandomValues(value);
  return bytesB64(value);
}

function canonicalRecord(value: Record<string, string>): Uint8Array {
  const keys = Object.keys(value).sort();
  const ordered: Record<string, string> = {};
  for (const key of keys) {
    const item = value[key];
    if (typeof item !== "string" || item.length === 0) throw new Error("CANONICAL_FIELD_INVALID");
    ordered[key] = item;
  }
  return new TextEncoder().encode(JSON.stringify(ordered) + "\n");
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyEd25519(publicKeyB64: string, signatureB64: string, data: Uint8Array): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", b64bytes(publicKeyB64), "Ed25519", false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, b64bytes(signatureB64), data);
  } catch {
    return false;
  }
}

function exactStringRecord(value: unknown, fields: readonly string[]): value is Record<string, string> {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).length === fields.length && fields.every(
    (field) => typeof record[field] === "string" && (record[field] as string).length > 0,
  );
}

const CHALLENGE_FIELDS = [
  "approval_id", "approval_policy_id", "controller_task_id", "operation_id", "operation_version",
  "provider", "requested_capability", "effect", "repo", "target_kind", "target_id",
  "expected_head_sha", "challenge_nonce", "signer_key_id", "broker_authority_id", "broker_epoch",
  "schema_version",
] as const;

const ACTIVATION_FIELDS = [
  "schema_version", "activation_policy_id", "activation_id", "ledger_object_id", "witness_object_id",
  "broker_authority_id", "broker_epoch", "ledger_recovery_nonce", "witness_recovery_nonce", "signer_key_id",
] as const;

const RECOVERY_FIELDS = [
  "schema_version", "recovery_policy_id", "recovery_id", "ledger_object_id", "witness_object_id",
  "broker_authority_id", "new_broker_epoch", "signer_key_id",
] as const;

function validChallenge(value: unknown): value is ChallengeV3 {
  return exactStringRecord(value, CHALLENGE_FIELDS) &&
    value.schema_version === CHALLENGE_SCHEMA && value.signer_key_id === APPROVAL_SIGNER;
}

function validActivation(value: unknown): value is ActivationCertificate {
  return exactStringRecord(value, ACTIVATION_FIELDS) &&
    value.schema_version === ACTIVATION_SCHEMA && value.signer_key_id === ADMIN_SIGNER;
}

function validRecovery(value: unknown): value is RecoveryAuthorization {
  return exactStringRecord(value, RECOVERY_FIELDS) &&
    value.schema_version === RECOVERY_SCHEMA && value.signer_key_id === ADMIN_SIGNER;
}

export async function deriveBrokerAuthority(ledgerId: string, witnessId: string): Promise<string> {
  if (!/^[0-9a-f]{64}$/.test(ledgerId) || !/^[0-9a-f]{64}$/.test(witnessId)) {
    throw new Error("DURABLE_OBJECT_ID_INVALID");
  }
  return sha256Hex(new TextEncoder().encode(`${AUTHORITY_LABEL}\n${ledgerId}\n${witnessId}\n`));
}

async function verifyActivationCertificate(
  cert: ActivationCertificate,
  signatureB64: string,
  adminPublicKeyB64: string,
): Promise<boolean> {
  if (!validActivation(cert)) return false;
  const authority = await deriveBrokerAuthority(cert.ledger_object_id, cert.witness_object_id);
  if (authority !== cert.broker_authority_id) return false;
  return verifyEd25519(adminPublicKeyB64, signatureB64, canonicalRecord(cert));
}

async function verifyRecoveryAuthorization(
  auth: RecoveryAuthorization,
  signatureB64: string,
  adminPublicKeyB64: string,
): Promise<boolean> {
  if (!validRecovery(auth)) return false;
  const authority = await deriveBrokerAuthority(auth.ledger_object_id, auth.witness_object_id);
  if (authority !== auth.broker_authority_id) return false;
  return verifyEd25519(adminPublicKeyB64, signatureB64, canonicalRecord(auth));
}

async function verifyApproval(
  challenge: ChallengeV3,
  signatureB64: string,
  approvalPublicKeyB64: string,
): Promise<boolean> {
  return validChallenge(challenge) && verifyEd25519(
    approvalPublicKeyB64, signatureB64, canonicalRecord(challenge),
  );
}

abstract class ActivationStore extends DurableObject<Env> {
  abstract readonly role: "ledger" | "witness";

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS control (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        state TEXT NOT NULL CHECK(state IN ('ACTIVE','RECOVERY_SUSPENDED')),
        broker_authority_id TEXT,
        broker_epoch TEXT,
        pending_epoch TEXT,
        local_recovery_nonce TEXT NOT NULL,
        activation_digest TEXT,
        activation_json TEXT,
        activation_signature_b64 TEXT
      );
    `);
    const existing = ctx.storage.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM control").one().n;
    if (existing === 0) {
      ctx.storage.sql.exec(
        "INSERT INTO control VALUES (1, 'RECOVERY_SUSPENDED', NULL, NULL, NULL, ?, NULL, NULL, NULL)",
        randomNonce(),
      );
    }
  }

  private control(): StoredControl {
    return this.ctx.storage.sql.exec<StoredControl>(
      "SELECT state, broker_authority_id, broker_epoch, pending_epoch, local_recovery_nonce, activation_digest, activation_json, activation_signature_b64 FROM control WHERE singleton=1",
    ).one();
  }

  private ownObjectMatches(cert: { ledger_object_id: string; witness_object_id: string }): boolean {
    const own = this.ctx.id.toString();
    return this.role === "ledger" ? cert.ledger_object_id === own : cert.witness_object_id === own;
  }

  async status(): Promise<BrokerStatus> {
    try {
      const row = this.control();
      if (row.state !== "ACTIVE") {
        return {
          decision: "RECOVERY_SUSPENDED",
          ...(row.pending_epoch ? { pending_epoch: row.pending_epoch } : {}),
          local_recovery_nonce: row.local_recovery_nonce,
        };
      }
      if (!row.activation_json || !row.activation_signature_b64 || !row.activation_digest ||
          !row.broker_authority_id || !row.broker_epoch) return { decision: "INTEGRITY_FAILED" };
      const cert = JSON.parse(row.activation_json) as unknown;
      if (!validActivation(cert) || !this.ownObjectMatches(cert)) return { decision: "INTEGRITY_FAILED" };
      if (cert.broker_authority_id !== row.broker_authority_id || cert.broker_epoch !== row.broker_epoch) {
        return { decision: "INTEGRITY_FAILED" };
      }
      const localNonce = this.role === "ledger" ? cert.ledger_recovery_nonce : cert.witness_recovery_nonce;
      if (localNonce !== row.local_recovery_nonce) return { decision: "INTEGRITY_FAILED" };
      const digest = await sha256Hex(canonicalRecord(cert));
      if (digest !== row.activation_digest) return { decision: "INTEGRITY_FAILED" };
      if (!(await verifyActivationCertificate(cert, row.activation_signature_b64, this.env.ADMIN_PUBLIC_KEY_B64))) {
        return { decision: "INTEGRITY_FAILED" };
      }
      return {
        decision: "ACTIVE",
        broker_authority_id: row.broker_authority_id,
        broker_epoch: row.broker_epoch,
        activation_digest: row.activation_digest,
        local_recovery_nonce: row.local_recovery_nonce,
      };
    } catch {
      return { decision: "INTEGRITY_FAILED" };
    }
  }

  async activate(cert: ActivationCertificate, signatureB64: string): Promise<{ decision: Decision; reason?: string }> {
    try {
      const row = this.control();
      if (row.state !== "RECOVERY_SUSPENDED") return { decision: "BLOCKED", reason: "NOT_SUSPENDED" };
      if (!validActivation(cert) || !this.ownObjectMatches(cert)) return { decision: "BLOCKED", reason: "ACTIVATION_BINDING_INVALID" };
      const localNonce = this.role === "ledger" ? cert.ledger_recovery_nonce : cert.witness_recovery_nonce;
      if (localNonce !== row.local_recovery_nonce) return { decision: "BLOCKED", reason: "RECOVERY_NONCE_MISMATCH" };
      if (row.pending_epoch && cert.broker_epoch !== row.pending_epoch) return { decision: "BLOCKED", reason: "PENDING_EPOCH_MISMATCH" };
      if (!(await verifyActivationCertificate(cert, signatureB64, this.env.ADMIN_PUBLIC_KEY_B64))) {
        return { decision: "BLOCKED", reason: "ACTIVATION_SIGNATURE_INVALID" };
      }
      const digest = await sha256Hex(canonicalRecord(cert));
      this.ctx.storage.transactionSync(() => {
        const current = this.control();
        if (current.state !== "RECOVERY_SUSPENDED" || current.local_recovery_nonce !== row.local_recovery_nonce ||
            current.pending_epoch !== row.pending_epoch) throw new Error("ACTIVATION_STATE_CHANGED");
        this.ctx.storage.sql.exec(
          "UPDATE control SET state='ACTIVE', broker_authority_id=?, broker_epoch=?, pending_epoch=NULL, activation_digest=?, activation_json=?, activation_signature_b64=? WHERE singleton=1",
          cert.broker_authority_id, cert.broker_epoch, digest,
          new TextDecoder().decode(canonicalRecord(cert)).trimEnd(), signatureB64,
        );
      });
      return { decision: "PASS" };
    } catch {
      return { decision: "BLOCKED", reason: "ACTIVATION_CONFLICT" };
    }
  }

  async suspendForRecovery(auth: RecoveryAuthorization, signatureB64: string): Promise<{ decision: Decision; reason?: string }> {
    if (!validRecovery(auth) || !this.ownObjectMatches(auth)) return { decision: "BLOCKED", reason: "RECOVERY_BINDING_INVALID" };
    if (!(await verifyRecoveryAuthorization(auth, signatureB64, this.env.ADMIN_PUBLIC_KEY_B64))) {
      return { decision: "BLOCKED", reason: "RECOVERY_SIGNATURE_INVALID" };
    }
    const current = await this.status();
    if (current.decision !== "ACTIVE" || current.broker_authority_id !== auth.broker_authority_id) {
      return { decision: "BLOCKED", reason: "RECOVERY_CURRENT_STATE_INVALID" };
    }
    try {
      this.ctx.storage.transactionSync(() => {
        const row = this.control();
        if (row.state !== "ACTIVE" || row.broker_authority_id !== auth.broker_authority_id ||
            row.activation_digest !== current.activation_digest) throw new Error("RECOVERY_STATE_CHANGED");
        this.ctx.storage.sql.exec(
          "UPDATE control SET state='RECOVERY_SUSPENDED', pending_epoch=? WHERE singleton=1",
          auth.new_broker_epoch,
        );
      });
      return { decision: "PASS" };
    } catch {
      return { decision: "BLOCKED", reason: "RECOVERY_CONFLICT" };
    }
  }

  async stageAfterRestore(auth: RecoveryAuthorization, signatureB64: string): Promise<{ decision: Decision; reason?: string; recovery_nonce?: string }> {
    if (!validRecovery(auth) || !this.ownObjectMatches(auth)) return { decision: "BLOCKED", reason: "RECOVERY_BINDING_INVALID" };
    if (!(await verifyRecoveryAuthorization(auth, signatureB64, this.env.ADMIN_PUBLIC_KEY_B64))) {
      return { decision: "BLOCKED", reason: "RECOVERY_SIGNATURE_INVALID" };
    }
    const nonce = randomNonce();
    try {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(
          "UPDATE control SET state='RECOVERY_SUSPENDED', broker_authority_id=NULL, broker_epoch=NULL, pending_epoch=?, local_recovery_nonce=?, activation_digest=NULL, activation_json=NULL, activation_signature_b64=NULL WHERE singleton=1",
          auth.new_broker_epoch, nonce,
        );
      });
      return { decision: "PASS", recovery_nonce: nonce };
    } catch {
      return { decision: "BLOCKED", reason: "RECOVERY_STAGE_FAILED" };
    }
  }

  protected async requireExpectedActive(expected: ExpectedActivation): Promise<boolean> {
    const status = await this.status();
    return status.decision === "ACTIVE" && status.activation_digest === expected.activation_digest &&
      status.broker_authority_id === expected.broker_authority_id && status.broker_epoch === expected.broker_epoch;
  }
}

export class BrokerWitnessDO extends ActivationStore {
  readonly role = "witness" as const;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS consumed (
        authorization_digest TEXT PRIMARY KEY,
        activation_digest TEXT NOT NULL,
        broker_epoch TEXT NOT NULL
      );
    `);
  }

  async has(authorizationDigest: string): Promise<boolean> {
    return this.ctx.storage.sql.exec<{ n: number }>(
      "SELECT COUNT(*) AS n FROM consumed WHERE authorization_digest=?", authorizationDigest,
    ).one().n === 1;
  }

  async reserve(authorizationDigest: string, expected: ExpectedActivation): Promise<{ decision: Decision; reason?: string }> {
    if (!/^[0-9a-f]{64}$/.test(authorizationDigest)) return { decision: "BLOCKED", reason: "DIGEST_INVALID" };
    try {
      return this.ctx.storage.transactionSync(() => {
        const row = this.ctx.storage.sql.exec<StoredControl>(
          "SELECT state, broker_authority_id, broker_epoch, pending_epoch, local_recovery_nonce, activation_digest, activation_json, activation_signature_b64 FROM control WHERE singleton=1",
        ).one();
        if (row.state !== "ACTIVE" || row.activation_digest !== expected.activation_digest ||
            row.broker_authority_id !== expected.broker_authority_id || row.broker_epoch !== expected.broker_epoch) {
          return { decision: "BLOCKED" as const, reason: "ACTIVATION_CHANGED" };
        }
        if (this.ctx.storage.sql.exec<{ n: number }>(
          "SELECT COUNT(*) AS n FROM consumed WHERE authorization_digest=?", authorizationDigest,
        ).one().n === 1) return { decision: "REPLAYED" as const, reason: "ALREADY_CONSUMED" };
        this.ctx.storage.sql.exec("INSERT INTO consumed VALUES (?, ?, ?)", authorizationDigest, expected.activation_digest, expected.broker_epoch);
        return { decision: "PASS" as const };
      });
    } catch {
      return { decision: "BLOCKED", reason: "WITNESS_CONFLICT" };
    }
  }
}

export class BrokerLedgerDO extends ActivationStore {
  readonly role = "ledger" as const;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS attempts (
        authorization_digest TEXT PRIMARY KEY,
        challenge_json TEXT NOT NULL,
        signature_b64 TEXT NOT NULL,
        signature_digest TEXT NOT NULL,
        activation_digest TEXT NOT NULL,
        broker_epoch TEXT NOT NULL,
        attempt_id TEXT NOT NULL UNIQUE
      );
    `);
  }

  async has(authorizationDigest: string): Promise<boolean> {
    return this.ctx.storage.sql.exec<{ n: number }>(
      "SELECT COUNT(*) AS n FROM attempts WHERE authorization_digest=?", authorizationDigest,
    ).one().n === 1;
  }

  private async validateStored(authorizationDigest: string): Promise<boolean> {
    try {
      const row = this.ctx.storage.sql.exec<Record<string, string>>(
        "SELECT * FROM attempts WHERE authorization_digest=?", authorizationDigest,
      ).toArray()[0];
      if (!row) return false;
      const challenge = JSON.parse(row.challenge_json) as unknown;
      if (!validChallenge(challenge)) return false;
      const digest = await sha256Hex(canonicalRecord(challenge));
      const sigDigest = await sha256Hex(b64bytes(row.signature_b64));
      return digest === authorizationDigest && sigDigest === row.signature_digest &&
        row.attempt_id === `attempt_${authorizationDigest}` &&
        await verifyApproval(challenge, row.signature_b64, this.env.APPROVAL_PUBLIC_KEY_B64);
    } catch {
      return false;
    }
  }

  async storeClaim(
    challenge: ChallengeV3,
    signatureB64: string,
    authorizationDigest: string,
    expected: ExpectedActivation,
  ): Promise<ClaimResult> {
    if (!validChallenge(challenge) || !(await verifyApproval(challenge, signatureB64, this.env.APPROVAL_PUBLIC_KEY_B64))) {
      return { decision: "BLOCKED", reason: "SIGNATURE_INVALID" };
    }
    if (await sha256Hex(canonicalRecord(challenge)) !== authorizationDigest) {
      return { decision: "BLOCKED", reason: "AUTHORIZATION_DIGEST_MISMATCH" };
    }
    try {
      const result = this.ctx.storage.transactionSync(() => {
        const row = this.ctx.storage.sql.exec<StoredControl>(
          "SELECT state, broker_authority_id, broker_epoch, pending_epoch, local_recovery_nonce, activation_digest, activation_json, activation_signature_b64 FROM control WHERE singleton=1",
        ).one();
        if (row.state !== "ACTIVE" || row.activation_digest !== expected.activation_digest ||
            row.broker_authority_id !== expected.broker_authority_id || row.broker_epoch !== expected.broker_epoch) {
          return { decision: "BLOCKED" as const, reason: "ACTIVATION_CHANGED" };
        }
        if (this.ctx.storage.sql.exec<{ n: number }>(
          "SELECT COUNT(*) AS n FROM attempts WHERE authorization_digest=?", authorizationDigest,
        ).one().n === 1) return { decision: "REPLAYED" as const, reason: "ALREADY_CLAIMED" };
        const challengeJson = new TextDecoder().decode(canonicalRecord(challenge)).trimEnd();
        this.ctx.storage.sql.exec(
          "INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?, ?)",
          authorizationDigest, challengeJson, signatureB64, "PENDING", expected.activation_digest,
          expected.broker_epoch, `attempt_${authorizationDigest}`,
        );
        return { decision: "PASS" as const };
      });
      if (result.decision !== "PASS") return result;
      const sigDigest = await sha256Hex(b64bytes(signatureB64));
      this.ctx.storage.sql.exec(
        "UPDATE attempts SET signature_digest=? WHERE authorization_digest=? AND signature_digest='PENDING'",
        sigDigest, authorizationDigest,
      );
      if (!(await this.validateStored(authorizationDigest))) return { decision: "BLOCKED", reason: "POSTWRITE_VERIFY_FAILED" };
      return { decision: "PASS", attempt_id: `attempt_${authorizationDigest}`, authorization_digest: authorizationDigest };
    } catch {
      return { decision: "BLOCKED", reason: "LEDGER_CONFLICT" };
    }
  }
}

async function runtimeRefs(env: Env) {
  const ledgerId = env.BROKER_LEDGER.idFromName(LEDGER_NAME);
  const witnessId = env.BROKER_WITNESS.idFromName(WITNESS_NAME);
  const ledgerObjectId = ledgerId.toString();
  const witnessObjectId = witnessId.toString();
  return {
    ledgerObjectId,
    witnessObjectId,
    brokerAuthorityId: await deriveBrokerAuthority(ledgerObjectId, witnessObjectId),
    ledger: env.BROKER_LEDGER.get(ledgerId),
    witness: env.BROKER_WITNESS.get(witnessId),
  };
}

export async function brokerRuntimeIdentity(env: Env) {
  const refs = await runtimeRefs(env);
  return {
    ledger_object_id: refs.ledgerObjectId,
    witness_object_id: refs.witnessObjectId,
    broker_authority_id: refs.brokerAuthorityId,
  };
}

export async function brokerStatus(env: Env): Promise<BrokerStatus> {
  const refs = await runtimeRefs(env);
  const [ledger, witness] = await Promise.all([refs.ledger.status(), refs.witness.status()]);
  if (ledger.decision !== "ACTIVE" || witness.decision !== "ACTIVE") return { decision: "RECOVERY_SUSPENDED" };
  if (ledger.broker_authority_id !== refs.brokerAuthorityId || witness.broker_authority_id !== refs.brokerAuthorityId ||
      ledger.broker_epoch !== witness.broker_epoch || ledger.activation_digest !== witness.activation_digest) {
    return { decision: "INTEGRITY_FAILED" };
  }
  return {
    decision: "ACTIVE",
    broker_authority_id: refs.brokerAuthorityId,
    broker_epoch: ledger.broker_epoch,
    activation_digest: ledger.activation_digest,
  };
}

export async function activateBroker(env: Env, cert: ActivationCertificate, signatureB64: string) {
  const refs = await runtimeRefs(env);
  if (cert.ledger_object_id !== refs.ledgerObjectId || cert.witness_object_id !== refs.witnessObjectId ||
      cert.broker_authority_id !== refs.brokerAuthorityId) return { decision: "BLOCKED" as const, reason: "RUNTIME_AUTHORITY_MISMATCH" };
  const witness = await refs.witness.activate(cert, signatureB64);
  if (witness.decision !== "PASS") return witness;
  const ledger = await refs.ledger.activate(cert, signatureB64);
  if (ledger.decision !== "PASS") return { decision: "BLOCKED" as const, reason: "PARTIAL_ACTIVATION" };
  const final = await brokerStatus(env);
  return final.decision === "ACTIVE" ? { decision: "PASS" as const } : { decision: "BLOCKED" as const, reason: "ACTIVATION_POSTVERIFY_FAILED" };
}

export async function claimBroker(env: Env, challenge: ChallengeV3, signatureB64: string): Promise<ClaimResult> {
  const refs = await runtimeRefs(env);
  const status = await brokerStatus(env);
  if (status.decision !== "ACTIVE" || !status.activation_digest || !status.broker_epoch) {
    return { decision: "BLOCKED", reason: "BROKER_NOT_ACTIVE" };
  }
  if (!validChallenge(challenge) || challenge.broker_authority_id !== refs.brokerAuthorityId || challenge.broker_epoch !== status.broker_epoch) {
    return { decision: "BLOCKED", reason: "CHALLENGE_AUTHORITY_OR_EPOCH_MISMATCH" };
  }
  if (!(await verifyApproval(challenge, signatureB64, env.APPROVAL_PUBLIC_KEY_B64))) {
    return { decision: "BLOCKED", reason: "SIGNATURE_INVALID" };
  }
  const digest = await sha256Hex(canonicalRecord(challenge));
  const [witnessHas, ledgerHas] = await Promise.all([refs.witness.has(digest), refs.ledger.has(digest)]);
  if (witnessHas || ledgerHas) {
    if (witnessHas && ledgerHas) return { decision: "REPLAYED", reason: "AUTHORIZATION_ALREADY_CONSUMED", authorization_digest: digest, attempt_id: `attempt_${digest}` };
    return { decision: "BLOCKED", reason: "PARTIAL_AUTHORIZATION_ALREADY_CONSUMED", authorization_digest: digest };
  }
  const expected: ExpectedActivation = {
    activation_digest: status.activation_digest,
    broker_authority_id: refs.brokerAuthorityId,
    broker_epoch: status.broker_epoch,
  };
  const reserved = await refs.witness.reserve(digest, expected);
  if (reserved.decision !== "PASS") {
    return reserved.decision === "REPLAYED"
      ? { decision: "BLOCKED", reason: "WITNESS_ALREADY_CONSUMED", authorization_digest: digest }
      : { decision: "BLOCKED", reason: reserved.reason ?? "WITNESS_REJECTED", authorization_digest: digest };
  }
  const stored = await refs.ledger.storeClaim(challenge, signatureB64, digest, expected);
  if (stored.decision !== "PASS") {
    return { decision: "BLOCKED", reason: "WITNESS_RESERVED_LEDGER_NOT_COMMITTED", authorization_digest: digest };
  }
  const [postStatus, postWitness, postLedger] = await Promise.all([
    brokerStatus(env), refs.witness.has(digest), refs.ledger.has(digest),
  ]);
  if (postStatus.decision !== "ACTIVE" || postStatus.activation_digest !== expected.activation_digest ||
      !postWitness || !postLedger) {
    return { decision: "BLOCKED", reason: "POSTCLAIM_VERIFY_FAILED", authorization_digest: digest };
  }
  return stored;
}

export async function suspendBrokerForRecovery(env: Env, auth: RecoveryAuthorization, signatureB64: string) {
  const refs = await runtimeRefs(env);
  if (auth.ledger_object_id !== refs.ledgerObjectId || auth.witness_object_id !== refs.witnessObjectId ||
      auth.broker_authority_id !== refs.brokerAuthorityId) return { decision: "BLOCKED" as const, reason: "RUNTIME_AUTHORITY_MISMATCH" };
  const [ledger, witness] = await Promise.all([
    refs.ledger.suspendForRecovery(auth, signatureB64), refs.witness.suspendForRecovery(auth, signatureB64),
  ]);
  return ledger.decision === "PASS" && witness.decision === "PASS"
    ? { decision: "PASS" as const }
    : { decision: "BLOCKED" as const, reason: "PARTIAL_RECOVERY_SUSPEND" };
}

export async function stageLedgerAfterRestore(env: Env, auth: RecoveryAuthorization, signatureB64: string) {
  const refs = await runtimeRefs(env);
  return refs.ledger.stageAfterRestore(auth, signatureB64);
}

export async function stageWitnessAfterRestore(env: Env, auth: RecoveryAuthorization, signatureB64: string) {
  const refs = await runtimeRefs(env);
  return refs.witness.stageAfterRestore(auth, signatureB64);
}

export default {
  async fetch(): Promise<Response> {
    return new Response("effect-free dual-do broker PoC", { status: 200 });
  },
} satisfies ExportedHandler<Env>;

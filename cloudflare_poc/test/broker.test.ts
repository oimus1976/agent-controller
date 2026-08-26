import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, inject, it } from "vitest";
import {
  BrokerLedgerDO,
  BrokerWitnessDO,
  activateBroker,
  brokerRuntimeIdentity,
  brokerStatus,
  claimBroker,
  stageLedgerAfterRestore,
  stageWitnessAfterRestore,
  suspendBrokerForRecovery,
  type ActivationCertificate,
  type RecoveryAuthorization,
} from "../src/index";

function canonical(value: Record<string, string>): Uint8Array {
  const ordered: Record<string, string> = {};
  for (const key of Object.keys(value).sort()) ordered[key] = value[key];
  return new TextEncoder().encode(JSON.stringify(ordered) + "\n");
}

function b64(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += String.fromCharCode(byte);
  return btoa(out);
}

async function sign(value: Record<string, string>, privateJwkJson: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "jwk", JSON.parse(privateJwkJson), "Ed25519", false, ["sign"],
  );
  return b64(new Uint8Array(await crypto.subtle.sign("Ed25519", key, canonical(value))));
}

async function sha(value: Record<string, string>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", canonical(value)));
  return [...digest].map((x) => x.toString(16).padStart(2, "0")).join("");
}

const adminPrivate = () => inject("adminPrivateJwk") as string;
const approvalPrivate = () => inject("approvalPrivateJwk") as string;

async function stubs() {
  return {
    ledger: env.BROKER_LEDGER.getByName("primary-ledger"),
    witness: env.BROKER_WITNESS.getByName("primary-witness"),
  };
}

async function activationCertificate(epoch: string, changes: Partial<ActivationCertificate> = {}) {
  const identity = await brokerRuntimeIdentity(env);
  const { ledger, witness } = await stubs();
  const [ledgerStatus, witnessStatus] = await Promise.all([ledger.status(), witness.status()]);
  if (!ledgerStatus.local_recovery_nonce || !witnessStatus.local_recovery_nonce) {
    throw new Error("RECOVERY_NONCES_UNAVAILABLE");
  }
  const cert: ActivationCertificate = {
    schema_version: "agent-controller-broker-activation-poc-v1",
    activation_policy_id: "activation-policy-poc-v1",
    activation_id: `activation-${epoch}`,
    ledger_object_id: identity.ledger_object_id,
    witness_object_id: identity.witness_object_id,
    broker_authority_id: identity.broker_authority_id,
    broker_epoch: epoch,
    ledger_recovery_nonce: ledgerStatus.local_recovery_nonce,
    witness_recovery_nonce: witnessStatus.local_recovery_nonce,
    signer_key_id: "human-admin-test-ephemeral",
    ...changes,
  };
  return { cert, signature: await sign(cert as unknown as Record<string, string>, adminPrivate()) };
}

async function activate(epoch = "epoch-poc-a") {
  const signed = await activationCertificate(epoch);
  const result = await activateBroker(env, signed.cert, signed.signature);
  expect(result.decision).toBe("PASS");
  const status = await brokerStatus(env);
  expect(status.decision).toBe("ACTIVE");
  expect(status.broker_epoch).toBe(epoch);
  return signed;
}

async function recoveryAuthorization(newEpoch: string) {
  const identity = await brokerRuntimeIdentity(env);
  const auth: RecoveryAuthorization = {
    schema_version: "agent-controller-broker-recovery-poc-v1",
    recovery_policy_id: "recovery-policy-poc-v1",
    recovery_id: `recovery-${newEpoch}`,
    ledger_object_id: identity.ledger_object_id,
    witness_object_id: identity.witness_object_id,
    broker_authority_id: identity.broker_authority_id,
    new_broker_epoch: newEpoch,
    signer_key_id: "human-admin-test-ephemeral",
  };
  return { auth, signature: await sign(auth as unknown as Record<string, string>, adminPrivate()) };
}

async function signedChallenge(epoch: string, changes: Record<string, string> = {}) {
  const identity = await brokerRuntimeIdentity(env);
  const challenge = {
    approval_id: `approval-${epoch}`,
    approval_policy_id: "policy-level3-v1",
    controller_task_id: "task-dual-do-poc",
    operation_id: "op-dual-do-poc",
    operation_version: "v1",
    provider: "codex",
    requested_capability: "MERGE_PR",
    effect: "MERGE",
    repo: "oimus1976/agent-controller",
    target_kind: "PULL_REQUEST",
    target_id: "999",
    expected_head_sha: "b".repeat(40),
    challenge_nonce: `challenge-${epoch}`,
    signer_key_id: "human-approval-test-ephemeral",
    broker_authority_id: identity.broker_authority_id,
    broker_epoch: epoch,
    schema_version: "agent-controller-approval-challenge-v3",
    ...changes,
  };
  return { challenge, signature: await sign(challenge, approvalPrivate()) };
}

async function snapshotControl(stub: any) {
  return runInDurableObject(stub, async (_instance, state) => {
    return state.storage.sql.exec<Record<string, string | null>>("SELECT * FROM control WHERE singleton=1").one();
  });
}

async function restoreControlForTest(stub: any, row: Record<string, string | null>) {
  await runInDurableObject(stub, async (_instance, state) => {
    state.storage.sql.exec(
      "UPDATE control SET state=?, broker_authority_id=?, broker_epoch=?, pending_epoch=?, local_recovery_nonce=?, activation_digest=?, activation_json=?, activation_signature_b64=? WHERE singleton=1",
      row.state, row.broker_authority_id, row.broker_epoch, row.pending_epoch, row.local_recovery_nonce,
      row.activation_digest, row.activation_json, row.activation_signature_b64,
    );
  });
}

describe("dual Durable Object broker authority", () => {
  it("starts suspended and derives namespace-bound runtime authority", async () => {
    const identity = await brokerRuntimeIdentity(env);
    expect(identity.ledger_object_id).toMatch(/^[0-9a-f]{64}$/);
    expect(identity.witness_object_id).toMatch(/^[0-9a-f]{64}$/);
    expect(identity.ledger_object_id).not.toBe(identity.witness_object_id);
    expect(identity.broker_authority_id).toMatch(/^[0-9a-f]{64}$/);
    expect((await brokerStatus(env)).decision).toBe("RECOVERY_SUSPENDED");
  });

  it("requires exact dual signed activation", async () => {
    const identity = await brokerRuntimeIdentity(env);
    const wrong = await activationCertificate("epoch-a", { ledger_object_id: "0".repeat(64) });
    expect((await activateBroker(env, wrong.cert, wrong.signature)).reason).toBe("RUNTIME_AUTHORITY_MISMATCH");
    expect((await brokerStatus(env)).decision).toBe("RECOVERY_SUSPENDED");

    await activate("epoch-a");
    const status = await brokerStatus(env);
    expect(status.broker_authority_id).toBe(identity.broker_authority_id);
  });

  it("claims a runtime-bound signed v3 once", async () => {
    await activate("epoch-claim");
    const signed = await signedChallenge("epoch-claim");
    const first = await claimBroker(env, signed.challenge, signed.signature);
    const second = await claimBroker(env, signed.challenge, signed.signature);
    expect(first.decision).toBe("PASS");
    expect(first.attempt_id).toBe(`attempt_${first.authorization_digest}`);
    expect(second.decision).toBe("REPLAYED");
  });

  it("wrong authority or epoch never reaches a logical claim", async () => {
    await activate("epoch-authority");
    const wrongAuthority = await signedChallenge("epoch-authority", { broker_authority_id: "1".repeat(64) });
    const wrongEpoch = await signedChallenge("epoch-old");
    expect((await claimBroker(env, wrongAuthority.challenge, wrongAuthority.signature)).decision).toBe("BLOCKED");
    expect((await claimBroker(env, wrongEpoch.challenge, wrongEpoch.signature)).decision).toBe("BLOCKED");
  });

  it("concurrent identical claims have at most one logical PASS", async () => {
    await activate("epoch-race");
    const signed = await signedChallenge("epoch-race");
    const results = await Promise.all([
      claimBroker(env, signed.challenge, signed.signature),
      claimBroker(env, signed.challenge, signed.signature),
    ]);
    expect(results.filter((x) => x.decision === "PASS")).toHaveLength(1);
    expect(results.filter((x) => x.decision !== "PASS")).toHaveLength(1);
  });

  it("witness-first partial claim remains consumed on ordinary retry", async () => {
    await activate("epoch-partial");
    const signed = await signedChallenge("epoch-partial");
    const status = await brokerStatus(env);
    const { witness } = await stubs();
    const digest = await sha(signed.challenge);
    const reserved = await witness.reserve(digest, {
      activation_digest: status.activation_digest!,
      broker_authority_id: status.broker_authority_id!,
      broker_epoch: status.broker_epoch!,
    });
    expect(reserved.decision).toBe("PASS");
    const retry = await claimBroker(env, signed.challenge, signed.signature);
    expect(retry).toEqual(expect.objectContaining({
      decision: "BLOCKED",
      reason: "PARTIAL_AUTHORIZATION_ALREADY_CONSUMED",
    }));
  });

  it("one-side consumed-record deletion cannot create a second PASS when counterpart remains", async () => {
    await activate("epoch-delete-one");
    const signed = await signedChallenge("epoch-delete-one");
    const first = await claimBroker(env, signed.challenge, signed.signature);
    expect(first.decision).toBe("PASS");
    const { witness } = await stubs();
    await runInDurableObject(witness, async (_instance, state) => {
      state.storage.sql.exec("DELETE FROM consumed WHERE authorization_digest=?", first.authorization_digest);
    });
    const replay = await claimBroker(env, signed.challenge, signed.signature);
    expect(replay.decision).toBe("BLOCKED");
    expect(replay.reason).toBe("PARTIAL_AUTHORIZATION_ALREADY_CONSUMED");
  });

  it("one-side activation tamper suspends the front gate", async () => {
    await activate("epoch-tamper");
    const { witness } = await stubs();
    await runInDurableObject(witness, async (_instance, state) => {
      state.storage.sql.exec("UPDATE control SET broker_epoch='epoch-attacker' WHERE singleton=1");
    });
    expect((await brokerStatus(env)).decision).not.toBe("ACTIVE");
  });

  it("claim CAS rejects a stale front activation after recovery starts", async () => {
    await activate("epoch-cas");
    const signed = await signedChallenge("epoch-cas");
    const before = await brokerStatus(env);
    const recovery = await recoveryAuthorization("epoch-cas-next");
    expect((await suspendBrokerForRecovery(env, recovery.auth, recovery.signature)).decision).toBe("PASS");
    const { witness } = await stubs();
    const result = await witness.reserve(await sha(signed.challenge), {
      activation_digest: before.activation_digest!,
      broker_authority_id: before.broker_authority_id!,
      broker_epoch: before.broker_epoch!,
    });
    expect(result).toEqual({ decision: "BLOCKED", reason: "ACTIVATION_CHANGED" });
  });

  it("witness reservation followed by recovery makes stale ledger write fail and stay consumed", async () => {
    await activate("epoch-cas-partial");
    const signed = await signedChallenge("epoch-cas-partial");
    const before = await brokerStatus(env);
    const { witness, ledger } = await stubs();
    const digest = await sha(signed.challenge);
    const expected = {
      activation_digest: before.activation_digest!,
      broker_authority_id: before.broker_authority_id!,
      broker_epoch: before.broker_epoch!,
    };
    expect((await witness.reserve(digest, expected)).decision).toBe("PASS");
    const recovery = await recoveryAuthorization("epoch-cas-partial-next");
    expect((await suspendBrokerForRecovery(env, recovery.auth, recovery.signature)).decision).toBe("PASS");
    expect((await ledger.storeClaim(signed.challenge, signed.signature, digest, expected)).decision).toBe("BLOCKED");
    expect((await claimBroker(env, signed.challenge, signed.signature)).decision).toBe("BLOCKED");
  });

  it("sequential restore interlock never resurrects dual ACTIVE old epoch", async () => {
    const oldActivation = await activate("epoch-before-restore");
    const { ledger, witness } = await stubs();
    const [oldLedger, oldWitness] = await Promise.all([snapshotControl(ledger), snapshotControl(witness)]);
    const recovery = await recoveryAuthorization("epoch-after-restore");
    expect((await suspendBrokerForRecovery(env, recovery.auth, recovery.signature)).decision).toBe("PASS");

    await restoreControlForTest(ledger, oldLedger);
    expect((await brokerStatus(env)).decision).not.toBe("ACTIVE");
    const ledgerStaged = await stageLedgerAfterRestore(env, recovery.auth, recovery.signature);
    expect(ledgerStaged.decision).toBe("PASS");
    expect((await brokerStatus(env)).decision).not.toBe("ACTIVE");

    await restoreControlForTest(witness, oldWitness);
    expect((await brokerStatus(env)).decision).not.toBe("ACTIVE");
    const witnessStaged = await stageWitnessAfterRestore(env, recovery.auth, recovery.signature);
    expect(witnessStaged.decision).toBe("PASS");
    expect((await brokerStatus(env)).decision).not.toBe("ACTIVE");

    const replayOldActivation = await activateBroker(env, oldActivation.cert, oldActivation.signature);
    expect(replayOldActivation.decision).toBe("BLOCKED");

    const fresh = await activationCertificate("epoch-after-restore");
    expect((await activateBroker(env, fresh.cert, fresh.signature)).decision).toBe("PASS");
    expect((await brokerStatus(env)).broker_epoch).toBe("epoch-after-restore");
  });

  it("old-epoch approval is unusable after supported recovery", async () => {
    await activate("epoch-old-approval");
    const oldApproval = await signedChallenge("epoch-old-approval");
    const { ledger, witness } = await stubs();
    const [oldLedger, oldWitness] = await Promise.all([snapshotControl(ledger), snapshotControl(witness)]);
    const recovery = await recoveryAuthorization("epoch-new-approval");
    await suspendBrokerForRecovery(env, recovery.auth, recovery.signature);
    await restoreControlForTest(ledger, oldLedger);
    await stageLedgerAfterRestore(env, recovery.auth, recovery.signature);
    await restoreControlForTest(witness, oldWitness);
    await stageWitnessAfterRestore(env, recovery.auth, recovery.signature);
    const fresh = await activationCertificate("epoch-new-approval");
    await activateBroker(env, fresh.cert, fresh.signature);
    expect((await claimBroker(env, oldApproval.challenge, oldApproval.signature)).decision).toBe("BLOCKED");
  });

  it("partial activation or recovery state never reports ACTIVE", async () => {
    const signed = await activationCertificate("epoch-half");
    const { witness } = await stubs();
    expect((await witness.activate(signed.cert, signed.signature)).decision).toBe("PASS");
    expect((await brokerStatus(env)).decision).not.toBe("ACTIVE");
  });

  it("production module exposes no external reset/delete/reclaim/PITR fetch surface", async () => {
    const ledgerMethods = Object.getOwnPropertyNames(BrokerLedgerDO.prototype);
    const witnessMethods = Object.getOwnPropertyNames(BrokerWitnessDO.prototype);
    for (const forbidden of ["reset", "delete", "reclaim", "restore", "bookmark", "pitr"] ) {
      expect(ledgerMethods.map((x) => x.toLowerCase())).not.toContain(forbidden);
      expect(witnessMethods.map((x) => x.toLowerCase())).not.toContain(forbidden);
    }
    const response = await (await import("../src/index")).default.fetch(new Request("https://example.test"), env, {} as ExecutionContext);
    expect(await response.text()).toBe("effect-free dual-do broker PoC");
  });

  it("Durable Object instances are the expected independent classes", async () => {
    const { ledger, witness } = await stubs();
    await runInDurableObject(ledger, async (instance) => expect(instance).toBeInstanceOf(BrokerLedgerDO));
    await runInDurableObject(witness, async (instance) => expect(instance).toBeInstanceOf(BrokerWitnessDO));
  });
});

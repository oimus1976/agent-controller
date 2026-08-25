import { env } from "cloudflare:workers";
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { BrokerDurableObject } from "../src/index";

const SIGNATURE = "p4DTQlILZY1hMYKGa2j37eEEBmZXldUd8uN4Z3mApg2BFy2+jmM3azUtyFndFHADJTdZZb7mSUzFrU54sD0iCQ==";

function challenge(changes: Record<string, string> = {}) {
  return {
    approval_id: "approval-poc-v3",
    approval_policy_id: "policy-level3-v1",
    controller_task_id: "task-poc-v3",
    operation_id: "op-poc-v3",
    operation_version: "v1",
    provider: "codex",
    requested_capability: "MERGE_PR",
    effect: "MERGE",
    repo: "oimus1976/agent-controller",
    target_kind: "PULL_REQUEST",
    target_id: "999",
    expected_head_sha: "b".repeat(40),
    challenge_nonce: "nonce-poc-v3-001",
    signer_key_id: "human-key-poc-v3",
    broker_authority_id: "broker-prod-primary",
    broker_epoch: "epoch-2026-08-25-a",
    schema_version: "agent-controller-approval-challenge-v3",
    ...changes,
  };
}

describe("effect-free broker Durable Object", () => {
  it("claims exact signed v3 once and replays the durable attempt", async () => {
    const stub = env.BROKER.getByName("claim-once");
    const first = await stub.claim(challenge(), SIGNATURE);
    const second = await stub.claim(challenge(), SIGNATURE);
    expect(first.decision).toBe("PASS");
    expect(second.decision).toBe("REPLAYED");
    expect(second.attempt_id).toBe(first.attempt_id);
    expect(await stub.count()).toBe(1);
  });

  it("concurrent claims have one logical first winner", async () => {
    const stub = env.BROKER.getByName("race");
    const results = await Promise.all([
      stub.claim(challenge(), SIGNATURE),
      stub.claim(challenge(), SIGNATURE),
    ]);
    expect(results.filter((r) => r.decision === "PASS")).toHaveLength(1);
    expect(results.filter((r) => r.decision === "REPLAYED")).toHaveLength(1);
    expect(await stub.count()).toBe(1);
  });

  it("wrong authority and old epoch block before insert", async () => {
    const authority = env.BROKER.getByName("wrong-authority");
    const epoch = env.BROKER.getByName("old-epoch");
    expect((await authority.claim(challenge({ broker_authority_id: "broker-attacker" }), SIGNATURE)).reason)
      .toBe("BROKER_AUTHORITY_MISMATCH");
    expect((await epoch.claim(challenge({ broker_epoch: "epoch-old" }), SIGNATURE)).reason)
      .toBe("BROKER_EPOCH_MISMATCH");
    expect(await authority.count()).toBe(0);
    expect(await epoch.count()).toBe(0);
  });

  it("recovery-suspended fixture blocks before insert", async () => {
    const stub = env.BROKER_SUSPENDED.getByName("recovery");
    const result = await stub.claim(challenge(), SIGNATURE);
    expect(result).toEqual({ decision: "BLOCKED", reason: "BROKER_RECOVERY_SUSPENDED" });
    expect(await stub.count()).toBe(0);
  });

  it("invalid signature blocks before insert", async () => {
    const stub = env.BROKER.getByName("bad-signature");
    const result = await stub.claim(challenge(), "AAAA");
    expect(result.reason).toBe("SIGNATURE_INVALID");
    expect(await stub.count()).toBe(0);
  });

  it("stored signature replacement blocks authoritative reread/replay", async () => {
    const stub = env.BROKER.getByName("tamper-signature");
    const first = await stub.claim(challenge(), SIGNATURE);
    expect(first.decision).toBe("PASS");
    await runInDurableObject(stub, async (instance, state) => {
      expect(instance).toBeInstanceOf(BrokerDurableObject);
      state.storage.sql.exec(
        "UPDATE attempts SET signature_b64 = ? WHERE authorization_digest = ?",
        "AAAA",
        first.authorization_digest,
      );
    });
    expect((await stub.claim(challenge(), SIGNATURE)).reason).toBe("STORED_AUTHORIZATION_INVALID");
  });

  it("self-consistent challenge/digest tamper still fails stored signature verification", async () => {
    const stub = env.BROKER.getByName("tamper-binding");
    const first = await stub.claim(challenge(), SIGNATURE);
    expect(first.decision).toBe("PASS");
    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql.exec<Record<string, string>>(
        "SELECT * FROM attempts WHERE authorization_digest = ?", first.authorization_digest,
      ).one();
      const changed = JSON.parse(row.challenge_json);
      changed.effect = "DEPLOY";
      const ordered: Record<string, string> = {};
      for (const key of Object.keys(changed).sort()) ordered[key] = changed[key];
      const bytes = new TextEncoder().encode(JSON.stringify(ordered) + "\n");
      const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
        .map((b) => b.toString(16).padStart(2, "0")).join("");
      state.storage.sql.exec(
        "UPDATE attempts SET challenge_json = ?, authorization_digest = ? WHERE authorization_digest = ?",
        JSON.stringify(ordered), digest, first.authorization_digest,
      );
    });
    const freshDigest = await runInDurableObject(stub, async (_instance, state) => {
      return state.storage.sql.exec<{ authorization_digest: string }>("SELECT authorization_digest FROM attempts").one().authorization_digest;
    });
    const replay = await stub.claim(challenge(), SIGNATURE);
    expect(replay.decision).toBe("PASS");
    expect(replay.authorization_digest).not.toBe(freshDigest);
    expect(await stub.count()).toBe(2);
  });

  it("anti-replay survives Durable Object eviction", async () => {
    const stub = env.BROKER.getByName("eviction");
    const first = await stub.claim(challenge(), SIGNATURE);
    expect(first.decision).toBe("PASS");
    await evictDurableObject(stub);
    const after = env.BROKER.getByName("eviction");
    const replay = await after.claim(challenge(), SIGNATURE);
    expect(replay.decision).toBe("REPLAYED");
    expect(replay.attempt_id).toBe(first.attempt_id);
  });
});

# Issue #316 — one-shot Phase 0 with a target-profile hold

Status: **code and fixtures only. Merging this grants no live authority.** The
one live run needs the owner's explicit decision below ([ADR #90](https://github.com/oimus1976/agent-controller/issues/90),
[rules §8](../governance/rules.md)).

## Why this shape

Phase 0 v3 reads the target's UserPolicy strictly from `HKU\<target SID>`. That
hive exists only while `ac-runner` is logged on, so Phase 0 cannot pass on an
idle host. Three ways to hold the hive during collection were compared:

| Option | What it needs | Verdict |
|---|---|---|
| A. Connect the #305 diagnostic supervisor to Phase 0 | New plan schema, new 12 s/25 s/60 s budgets for a collector that also calls GitHub, re-freeze and re-review of 32 KB of candidate bytes, separate Decisions A and B, a UTC window | Rejected: most review surface, most ceremony |
| **B. One owner-launched Python command with a small hold child** | ~140 lines of PowerShell 5.1, one Python module, the deferred-commit primitive already in this PR | **Chosen** |
| C. Manual `runas /profile` window plus the existing CLI | No code | Rejected: the existing CLI writes canonical PASS before release, and no creation handle is retained |

B reuses the reviewed pieces unchanged: the strict collector
(`collect_validated_phase0_evidence`), the freeze, the #270 `Process.Start`
launch shape, the #305 child/lease idea and state observations.

## What one run does

`python.exe -s -E -B -m scripts.collect_private_ci_phase0_with_target_hold --expected-freeze-sha256 <sha>`
from the frozen controller tree, as non-elevated `<HOST>\c-admin`:

1. **Read-only checks.** Canonical slot empty, freeze digest, tree binding,
   target idle (hive not mounted, profile not loaded, no session, enabled,
   non-admin). Any failure stops with no effect. `--preflight-only` ends here.
2. **Credential dialog.** The hold child (`scripts/Issue316-TargetProfileHold.ps1`)
   opens the Windows credential dialog. The human types the `ac-runner`
   password there. Cancel stops with no effect. The password exists only as a
   `SecureString` in that child; it is never on a command line, pipe, file or log.
3. **Hold.** One fixed non-admin target child starts with its profile loaded
   and waits on stdin. It runs no repository code. The parent then observes
   `HKU\<SID>` mounted with a fresh process.
4. **Collect.** The unchanged strict Phase 0 v3 collector runs. The validated
   bytes stay in memory. A missing, unreadable or malformed policy blocks.
5. **Release and verify.** The child is released and its exit is confirmed on
   the retained creation handle. A fresh observation must then show the hive
   unmounted, profile unloaded, no session, and account/profile/ACL facts equal
   to the baseline (polled for up to 90 s).
6. **Commit.** Only then is `issue216-phase0-canonical.json` created
   exclusively and read back, and `PHASE0_PASS` printed. A transcript
   `issue216-phase0-target-hold-<UTC>.log` is written to the evidence root.

## Outcomes

| Exit | Meaning | Canonical file |
|---|---|---|
| 0 `PHASE0_PASS` | Collected while held, release and restoration verified | written |
| 2 `BLOCKED` | A check or the collection failed; the profile is verified restored or was never touched | not written |
| 3 `STOP_PARTIAL_PROFILE_STATE` | Restoration is not proven (unknown child exit, logon possibly in flight, profile still loaded, baseline drift) | not written |

There is no retry, unload, kill-by-PID or repair path. After exit 3 the host
needs a separate human recovery decision. If the exclusive write succeeds but
the readback differs, the file is left in place so the slot stays occupied;
that also needs a human decision.

## #195 mapping

The general #195 gate attests PowerShell candidates through the AST producer.
It has no effect family for this launcher, and extending it would cost more
than the whole change. So this is **not** a `PASS_TO_OPERATOR` result. What the
one-shot provides instead, deterministically and fail-closed:

| #195 requirement | Here |
|---|---|
| Frozen contract, not agent-written shell text | Fixed command; only variable is the freeze SHA-256, checked against the file |
| Exact repo/PR/SHA/host/identity binding | Freeze + collector (clean tree, HEAD = remote `main` = frozen SHA); hold child rechecks host, identity, non-elevation, SID |
| Evidence root and transcript | Fixed `C:\Users\Public\Documents\agent-controller-handoff`, exclusive transcript |
| Windows PowerShell 5.1 | Hold child asserts 5.1 x64; parsed and exercised on 5.1 in CI |
| Child exit code, fail-fast, success marker | Retained-handle exit code, every stage deadline-bound, `PHASE0_PASS` only after commit |
| Authenticated AST/effect attestation | **Not provided.** Covered by the owner's one-off exception below |

## The one owner decision

After this PR is independently reviewed and merged by the human:

> Authorize exactly one run of the reviewed one-shot at the merged `main`
> commit: one `ac-runner` logon/profile load on `<HOST>`, strict Phase 0
> collection, release and verification, as a one-off #195 exception for this
> command only. Password entered only in the Windows dialog. No retry.
> No runner registration, JIT credential, workflow dispatch or target code.

Known residual effects of a normal profile load: Windows may update
`NTUSER.DAT`, its logs and profile timestamps. Content immutability is not
promised; ACLs and account facts are compared.

Not covered by fixtures and only observable in the real run: that the
non-elevated broker can read `HKU\<SID>` policy while the target is logged on,
and that Windows unloads the profile promptly after the child exits. Either
failing produces exit 2 or 3, never PASS.

Old authority is not reused: the #305 Decision B
([#6504106268](https://github.com/oimus1976/agent-controller/issues/305#issuecomment-6504106268))
expired unused, and #305 Decision A covers different bytes.

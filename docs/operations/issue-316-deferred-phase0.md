# Issue #316 — one-shot Phase 0 with a target-profile hold

Status: **code and fixtures only. Merging this grants no live authority.** The
one live run needs the owner's explicit decision below ([ADR #90](https://github.com/oimus1976/agent-controller/issues/90),
[rules §8](../governance/rules.md)).

> **Open blocker found in review (2026-11-11): the broker probably cannot read
> the target hive at all.** See [Expected denial](#expected-denial-of-the-broker-side-policy-read).
> Do not request the live run until the owner has chosen how to resolve it.

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
| 3 `STOP_PARTIAL_PROFILE_STATE` | Restoration is not proven (unknown child exit, logon possibly in flight, credential dialog left open past 300 s, collection longer than the 240 s hold, profile still loaded, baseline drift) | not written |
| 4 `STOP_CANONICAL_READBACK_MISMATCH` | The exclusive write happened but the readback differs | left in place, not usable |

There is no retry, unload, kill-by-PID or repair path. After exit 3 the host
needs a separate human recovery decision. After exit 4 the mismatching file is
left in place so the slot stays occupied; that also needs a human decision.

## Expected denial of the broker-side policy read

Phase 0 v3 (#303) and the #305 design both assume that the non-elevated broker
can open `HKU\<target SID>` once the target is logged on. Read-only
observations on the pilot host on 2026-11-11 make that unlikely:

- the broker account is a standard user: its token has no
  `BUILTIN\Administrators` group, not even deny-only;
- from that account, `Registry.Users.OpenSubKey` is denied for the other
  principals' loaded hives (`S-1-5-19`, `S-1-5-20`) and succeeds only for its
  own hive, `.DEFAULT` and `S-1-5-18`;
- a local profile hive normally grants access to its owner, SYSTEM and
  Administrators only.

The target hive itself has never been observed loaded from the broker, so this
is an expectation, not a measurement. If it holds, a live run of this one-shot
ends `BLOCKED` (exit 2) in the unchanged collector with "target UserPolicy SID
hive/policy unreadable", after one real logon and a verified restore. It cannot
produce a false PASS. The mount check itself uses name enumeration and does not
need read access.

Ways forward, an owner decision because each changes what Phase 0 evidence means:

1. **Measure inside the target.** Let the fixed target child read its own
   `HKCU` policy with the same strict reader and report it; record the source
   in the evidence. Smallest change, and no hold across collection is needed.
   It replaces "broker-observed" with "reported by the fixed command running as
   the target", which #305 explicitly declined.
2. **Run this one-shot once as the measurement.** Costs one authorized logon
   that most likely ends `BLOCKED`, and then still needs option 1 or 3.
3. **Collect from an elevated administrator.** The broker account is not an
   administrator, so this needs a second account and reverses the
   non-elevated-broker rule. Not recommended.

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
| Child exit code, fail-fast, success marker | Retained-handle exit code; hold stages are deadline-bound and the 240 s hold bounds the collector (its own calls have no timeout); `PHASE0_PASS` only after commit |
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

Not covered by fixtures and only observable in a real run: whether Windows
unloads the profile and drops the logon session promptly after the child exits
(a lingering session yields a false exit 3), and the broker-side hive read
discussed above. Neither can produce a PASS.

Old authority is not reused: the #305 Decision B
([#6504106268](https://github.com/oimus1976/agent-controller/issues/305#issuecomment-6504106268))
expired unused, and #305 Decision A covers different bytes.

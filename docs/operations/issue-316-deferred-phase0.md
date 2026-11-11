# Issue #316 — one-shot Phase 0 with a target-profile hold

Status: **code and fixtures only. Merging this grants no live authority.** The
one live run needs the owner's explicit decision below ([ADR #90](https://github.com/oimus1976/agent-controller/issues/90),
[rules §8](../governance/rules.md)).

> **Owner decision 2026-11-11:** run the one-shot once from an **elevated**
> console of the broker account. See [Broker-side hive read](#broker-side-hive-read).

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
from the frozen controller tree, in an **elevated** console of `<HOST>\c-admin`:

1. **Read-only checks.** Canonical slot empty, freeze digest, tree binding,
   console elevated (a non-elevated launch stops here with no effect),
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

## Broker-side hive read

Phase 0 v3 (#303) and the #305 design both assume that the non-elevated broker
can open `HKU\<target SID>` once the target is logged on. Read-only
observations on the pilot host on 2026-11-11 make that unlikely:

- the broker account is a member of Administrators, but the normal broker
  process runs a UAC-filtered medium-integrity token in which
  `BUILTIN\Administrators` is "deny only", so that membership grants nothing;
- from that token, `Registry.Users.OpenSubKey` is denied for the other
  principals' loaded hives (`S-1-5-19`, `S-1-5-20`) and succeeds only for its
  own hive, `.DEFAULT` and `S-1-5-18`;
- a local profile hive normally grants access to its owner, SYSTEM and
  Administrators only.

The target hive itself has never been observed loaded, so the denial is an
expectation, not a measurement. The same holds for the remedy: that an
elevated token of the same account can read it is the normal Windows default
and has not been measured on this host either.

**Decision (owner, 2026-11-11): run this one-shot once from an elevated
console of the broker account.** The strict collector and the meaning of the
evidence stay unchanged: the policy is still observed by the broker, not
reported by the target. The alternatives were measuring inside the target
child (changes the evidence source, which #305 declined) and running
non-elevated as a measurement (expected `BLOCKED`).

What elevation changes, and what it does not:

- It is an exception to the non-elevated-broker rule, limited to this
  read-only collection. Later pilot phases keep that rule.
- `git`, `gh`, PowerShell and Python run with full administrator rights for
  the duration of the run. They execute only the frozen controller tree
  (clean, `HEAD` = remote `main` = freeze) and read-only queries.
- The target child is still a separate `ac-runner` logon without
  administrator rights; it refuses to run as an administrator and receives no
  broker environment or credential.
- An elevated token sees every logon session. If Windows keeps the target's
  session listed after the child exits, the run ends with exit 3 even though
  the profile is unloaded.
- The hold child refuses a non-elevated launch before the credential dialog,
  so a wrong console costs nothing.

If the hive read is denied even when elevated, the run ends `BLOCKED` (exit 2)
in the unchanged collector, or exit 3 if the restore cannot be verified. It
cannot produce a false PASS.

## #195 mapping

The general #195 gate attests PowerShell candidates through the AST producer.
It has no effect family for this launcher, and extending it would cost more
than the whole change. So this is **not** a `PASS_TO_OPERATOR` result. What the
one-shot provides instead, deterministically and fail-closed:

| #195 requirement | Here |
|---|---|
| Frozen contract, not agent-written shell text | Fixed command; only variable is the freeze SHA-256, checked against the file |
| Exact repo/PR/SHA/host/identity binding | Freeze + collector (clean tree, HEAD = remote `main` = frozen SHA); hold child rechecks host, identity, elevation, SID |
| Evidence root and transcript | Fixed `C:\Users\Public\Documents\agent-controller-handoff`, exclusive transcript |
| Windows PowerShell 5.1 | Hold child asserts 5.1 x64; parsed and exercised on 5.1 in CI |
| Child exit code, fail-fast, success marker | Retained-handle exit code; hold stages are deadline-bound and the 240 s hold bounds the collector (its own calls have no timeout); `PHASE0_PASS` only after commit |
| Authenticated AST/effect attestation | **Not provided.** Covered by the owner's one-off exception below |

## The one owner decision

After this PR is independently reviewed and merged by the human:

> Authorize exactly one run of the reviewed one-shot at the merged `main`
> commit, from an elevated console: one `ac-runner` logon/profile load on
> `<HOST>`, strict Phase 0 collection, release and verification, as a one-off
> #195 exception and a one-off exception to the non-elevated-broker rule for
> this command only. Password entered only in the Windows dialog. No retry.
> No runner registration, JIT credential, workflow dispatch or target code.

Known residual effects of a normal profile load: Windows may update
`NTUSER.DAT`, its logs and profile timestamps. Content immutability is not
promised; ACLs and account facts are compared.

Not covered by fixtures and only observable in a real run: whether Windows
unloads the profile and drops the logon session promptly after the child exits
(a lingering session yields a false exit 3), and the elevated hive read
discussed above. Neither can produce a PASS.

Old authority is not reused: the #305 Decision B
([#6504106268](https://github.com/oimus1976/agent-controller/issues/305#issuecomment-6504106268))
expired unused, and #305 Decision A covers different bytes.

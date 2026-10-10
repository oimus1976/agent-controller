# Issue #305 — STOP at synthetic privilege/broker boundary

Disposition: **NO_SAFE_OPERATOR_ORCHESTRATION / NOT READY FOR DECISION A OR B**.
This packet records a stopped feasibility pass, not a completed live candidate or
an executable owner command. #195 remains generally BLOCKED, Phase 0 readiness
remains BLOCKED, and the pilot is NOT PASS.

Authority is [#305 comment 6095683027](https://github.com/oimus1976/agent-controller/issues/305#issuecomment-6095683027),
with [parent #216 continuation](https://github.com/oimus1976/agent-controller/issues/216#issuecomment-6095684935)
and [MVP #297](https://github.com/oimus1976/agent-controller/issues/297).
Fresh GitHub main was `15459e4395e7ab228e1c140b04256e569643f9b9`;
no open PRs were observed at entry. No #302 script, plan or approval was used.

## What was implemented and observed

`scripts/Test-Issue305HiveBoundary.ps1` is a Windows PowerShell 5.1 x64
**fixture feasibility candidate only**, accepting no target paths or parameters.
It creates a new synthetic private application hive in an absent GUID temporary
directory, writes synthetic AllSigned values, closes handles, then attempts one
native RegLoadKeyW into a freshly generated `AC305_FIXTURE_<GUID>` key.
Every post-success load path enters `finally` and attempts only its owned unload.
A separate PowerShell child checks the exact synthetic key is absent before
fixture deletion; source/sentinel readback is captured before that deletion.
Its fixed bytes and effect inventory are in `fixture-plan.json`. The plan is a
fixture plan, not a populated live approval plan. There is no live mode.

Executed outcome (`fixture-result.json`, transcribed from tool stdout):

- Windows PowerShell `5.1.26100.9444`; non-elevated token.
- Private synthetic app-hive creation succeeded.
- Global synthetic load returned **1314 (ERROR_PRIVILEGE_NOT_HELD)**.
- Collector child was never started and unload was not attempted because no
  mount was acquired. Independent readback found the synthetic key absent.
- Synthetic source SHA-256 before/after was identical; excluded sentinel was
  unchanged; disposable directory was removed.
- The shell reported nonzero status. The fixture script always requests exit 2
  and never grants operator authority, even on a hypothetical same-token success.

Read-only `whoami /priv` independently showed only SeChangeNotifyPrivilege and
SeIncreaseWorkingSetPrivilege in the available broker token. SeBackupPrivilege
and SeRestorePrivilege were absent. This is not the elevated loader token.

## Why this stops

The available token cannot mount even the synthetic hive. This **does not prove
that an owner-elevated fixture or actual RegLoadKey can never work**. It means
this pass has no native proof for the required elevated loader → non-elevated
broker read → loader unload handoff. Even a successful same-token child read
would not prove that boundary. No UAC launch or simulated success was promoted
into native proof, and no real-profile experiment was attempted.

The unchanged normal collector executes separate subprocesses without timeouts
(`private_ci_phase0_collector.py::_default_command_runner`). A ten-minute mount
promise therefore also needs a demonstrated completion/cancellation handoff:
normal broker collection while mounted, exact exit/evidence readback, closure
of operation-owned handles, and unload on failure/timeout. None is demonstrated
by this failed fixture. Rather than add a scheduler, daemon, profile manager,
token broker or generic gate family, stop at this evidence boundary.

This is a missing proof for the current #305 acceptance, not a diagnosis of the
real hive, a host-policy PASS, or a new generalized hardening workstream.

## Validation and review preparation

- Windows PowerShell 5.1 parser: PASS, zero parse errors.
- Existing `test_private_ci_phase0_policy_windows.py`: **5 tests PASS**,
  covering target SID selection, missing/unreadable/malformed policy, handle
  closure and MachinePolicy precedence using in-memory fixtures.
- Existing `test_private_ci_phase0_collector.py`: **9 tests PASS**.
- New native synthetic boundary fixture: **BLOCKED (1314)**, with negative-path
  cleanup/readback as above. Positive mounted cross-integrity access, load-success
  error/unload-failure paths, live binding drift, ten-minute timeout and live
  exclusion readbacks are **NOT TESTED**, not assumed passed.
- Independent exact-commit review is requested separately. Self-checks are L0;
  no canonical `inspect-pr` clean-review verdict is claimed in this packet.

## Later human scope, if a safe fixture path is separately established

Neither decision is currently granted or requested as executable:

1. **Decision A:** accept a NEW exact one-off manual #195 exception, with the
   complete reviewed live candidate/plan SHA-256 and size, the general gate
   still BLOCKED, and real hive/log OS side effects explicitly accepted.
2. **Decision B:** after fresh GitHub/local preflight and separately authorized
   fresh freeze, authorize one actual ten-minute load/normal-broker Phase 0 v3/
   unload/readback window on the freshly rebound target account/SID/profile.
   Candidate and plan bytes must be reviewed and fixed before that operation.

Required live plan fields are not invented here: current controller tree/SHA,
private target repo/open same-repo PR/head SHA, trusted workflow SHA/path,
new freeze SHA/nonce, broker identity/token context, full freshly resolved target
SID, both matching profile paths, source hash/size/ACL, exact outputs, timestamps
and the 600-second window. No old SHA, nonce or approval is a current binding.

Expected sequence, only a proposal: new target binding/freeze → absence and
profile-use checks → one elevated exact-SID load → actual lower broker's strict
policy probe and normal collector while mounted → evidence SHA/binding readback
→ close owned handles → one unload → independent HKU absence/profile/source/
exclusion readback → STOP for the next separate live gate. If load fails, no
retry/repair. If collector fails, unload still attempted. If unload/timeout/
poststate is uncertain, preserve evidence and STOP; no forced unload, unrelated
process kill, reboot, overwrite, runner registration or dispatch.

Remaining real-target risks include rejected NTUSER.DAT, OS hive/log persistence
or changed bytes, concurrent profile use, lower-broker HKU ACL denial, stuck
collector or registry handles, and unload failure. A changed source hash must be
reported for human assessment, never silently restored. Persisted Phase 0 is an
observed snapshot; the later human live gate must make a bounded freshness
judgment and stop on intervening relevant policy/profile drift.

No real target profile/hive operation, actual freeze, canonical Phase 0 output,
credential, runner, dispatch, account/group/ACL/policy change or old-generation
cleanup was performed. The production collector and #195 gate are unchanged.

## Prior art / reuse

Use the official Windows registry APIs and the existing normal v3 collector.
The fixture wrapper exists only to obtain native evidence; no production
framework or alternative policy parser is introduced. Microsoft documents
[RegLoadKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadkeyw)
and [RegUnLoadKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regunloadkeyw)
as requiring backup/restore privileges. [AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)
cannot add absent privileges. [RegLoadAppKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadappkeyw)
creates an empty private hive at an absent file, which is the synthetic source
creation selected here; this is not the prior failed real-hive-copy experiment.

# #310: one #305 exact execution handoff (Draft / non-live)

This implements the missing bridge identified by [STOP #6251147849](https://github.com/oimus1976/agent-controller/issues/305#issuecomment-6251147849).
It grants no execution authority. Development uses synthetic data only. Original
[A](https://github.com/oimus1976/agent-controller/issues/305#issuecomment-6104605714)
stays `APPROVED_UNUSED`; its [four-field amendment](https://github.com/oimus1976/agent-controller/issues/305#issuecomment-6244245123)
is preserved. [Old B](https://github.com/oimus1976/agent-controller/issues/305#issuecomment-6251090806)
expired at **2026-10-18T14:35:02Z** and cannot authorize these artifacts.

## Smallest selected mechanism

Reuse the unchanged [#305 candidate](issue-305-target-context/README.md), its
retained process handles, target lease, strict broker HKU reader and independent
broker postread. The added code is a single-operation Python byte assembler and
Windows PowerShell 5.1 owner entry; no Controller/Phase0 change, approval service,
signing infrastructure or generalized framework. Standard `FileMode.CreateNew`
provides the exclusive reservation, `Get-Credential` provides human secure input,
and GitHub REST GET reads public authority. The custom part binds these to #305's
exact bytes and human boundary. This removes the concrete repeated expiring-B /
non-executable-schema blocker without replacing the reviewed native diagnostic.

## Immutable preparation, no authority

After human merge, a **separate fresh native read-only binding** must first match
original A plus its amendment. Do not run native binding or this entry during
the #310 development session. In particular, fixtures do not demonstrate native
loaded-hive access, policy compatibility, profile restoration or live readiness.

`scripts/issue310_handoff.py` accepts one ASCII JSON preparation spec, schema
`issue310.preparation.v1`, with exactly these fields:

| Field | Meaning |
|---|---|
| `proposal` | Pin to a **new**, immutable `issue305.decision-b-plan.NON_EXECUTABLE.v2` proposal, false B/execution flags and null live binding. Historical files are never edited. |
| `baseline` | Pin to the fresh native facts object returned by `Get-Issue310NativeFacts` in this reviewed entry, without credentials or target operations. Missing/access-denied facts block; never supply fabricated zero/absent facts. |
| `approved_scope` | Pin to `issue-310-approved-scope.json`, the fixed projection of unchanged A plus the four-field delta. Both implementations pin normalized LF SHA `121ce884b3f6994cc6d87fff9d7a8899b63d8af9ec5bca680c48a008cd081a3d`; a new baseline cannot redefine these facts. |
| `candidate` | Pin to actual approved Windows CRLF candidate, `c135d935…2ec571`, 32421 bytes; no regeneration/normalization at execution. |
| `entry` | Pin to actual merged `scripts/Issue310-ExactHandoff.ps1` Windows file bytes. |
| `authority` | `main_sha` (40 lowercase hex); `a_body_sha256`, `delta_body_sha256` (SHA256 of GitHub comment body's exact UTF-8 text); `latest216`, `latest195` (latest comment IDs). Re-read all on GitHub. |
| `packet_path`, `plan_path` | Exact absolute destinations in a new private review packet directory. No quotes/control characters, UNC, reparse ancestors or path normalization drift. |

Every pin is exactly `{ "path": <absolute path>, "sha256": <64 lowercase hex>,
"bytes": <integer> }`. The assembler checks input hashes and A/delta subject/runtime,
derives only the candidate's 14-field live shape from `prospective_operation_binding`,
and exclusively creates the prospective plan and packet. Output encoding is ASCII
(thus UTF-8 without BOM), sorted keys, two-space indentation, LF, one trailing LF;
the packet records the exact plan raw SHA/size. The true flags describe **prospective
bytes for review**; they do not confer authority. Python never starts a child,
calls GitHub, prompts for secrets, selects a current UTC window or changes a source.

Preparation invocation pattern, with already reviewed literal values substituted:

```text
python scripts/issue310_handoff.py <preparation-spec.json> --expected-spec-sha256 <spec-raw-sha256>
```

It emits `PREPARED_FOR_OWNER_B: prospective bytes only; authority=false`.
An existing/partial output is not overwritten. Packet/plan raw bytes and SHA/size,
actual code/candidate pins, full native baseline, invocation template and frozen
240–600-second UTC window must all be reviewed **before** the later owner B.
Preparation never chooses, extends or starts a countdown. Schedule the immutable
prospective window for a later deliberate owner-present stage; if it expires,
stop. A replacement packet/window needs fresh read-only binding and a new B.

The PowerShell `PREPARED_FOR_OWNER_B` stage validates file/schema pins and renders
the exact proposed B text. It performs no target observation or credential/claim
operation and does not declare native readiness. Its input is still a prospective
packet, not the old approved JSON. Baseline acquisition is a separate read-only
operation, subject to the same governance; the function is available for that
later reviewed binding. [Original A's checkpoint #6103856605](https://github.com/oimus1976/agent-controller/issues/305#issuecomment-6103856605)
records **139 unreadable process owners** under the normal token. The
[owner decision #6339925221](https://github.com/oimus1976/agent-controller/issues/310#issuecomment-6339925221)
removed the universal owner-SID requirement. A later non-elevated
[read-only feasibility observation #6342086088](https://github.com/oimus1976/agent-controller/issues/310#issuecomment-6342086088)
found **134 NULL ExecutablePath values in 247 processes** (including PID0;
133 excluding PID0), showing that universal image-path readability also fails.
The [new human decision #6342893201](https://github.com/oimus1976/agent-controller/issues/310#issuecomment-6342893201)
accepts **incomplete ambient process visibility as a disclosed risk** and permits
this second narrow remediation, not a wider live effect or new B approval.

### Scoped process observation and its limits

Before considering processes, independently verify exact target SID, enabled
non-admin account, matching ProfileList/profile/source baseline, `Loaded=false`,
both exact HKU SID and SID_Classes absent, zero target logon sessions and
operation/authority/output absence. Unknown or contradictory *target* facts STOP.
Process metadata discovery requests only PID, parent PID, session ID, name
and optional ExecutablePath, with a 4096-record ceiling; no command lines,
arguments or environment. Missing/invalid PID, parent/session or **non-string/blank name**, duplicate
PIDs and over-limit inventory STOP. The exact PID0 idle accounting record
is excluded from ownership/visibility counts; PID4 is **not** a privileged
exception or declared safe.

Positively identified **operation-related candidates** include script hosts
(PowerShell, PowerShell ISE, pwsh, cmd, wscript, cscript, mshta, conhost and
OpenConsole), the bound operation PID, any *available* image-path match within
the exact target profile, candidate/entry or claim directories, and descendants
of those candidates, including descendants of a bound operation PID which is
already absent. An available script-host **image basename** and a drive-rooted image path
whose normalized form enters an operation directory are positive candidate
evidence even when the reported Name or raw path conflicts. These cases must
STOP on the mandatory canonical image/name verification; they cannot enter the
ambient visibility fallback. A runner/actions name or an available image path
containing runner/actions STOP immediately, irrespective of ownership. Relevant process
owners are checked through `GetOwnerSid`, **but only after** a canonical exact
image-path/name match is established. A NULL/malformed/mismatched image,
unknown owner, target SID match or unverifiable lineage in this positively
identified candidate set STOP. Services/tasks with runner/actions indicators
or the exact target principal also STOP.

**Ambient PIDs not positively associated with the operation** do not receive
an owner lookup. If `ExecutablePath` is NULL, inaccessible, malformed or
noncanonical on such an ambient PID, it is counted as incomplete visibility,
not treated as unrelated/safe, nor inferred to be a Windows system process.
The observation explicitly reports `limitation=UNVERIFIED_AMBIENT_PROCESS_VISIBILITY`,
`ownership_complete=false`, `unverified_ambient_process_count`,
`unverified_ambient_image_path_count` and `image_path_complete`.
The ambient count includes all non-candidate PIDs not queried; the image count
includes only their unavailable/noncanonical image paths. Counts are not access
denial counts and do not prove their owners, absence of a hidden target process,
or **global host quiescence**. Known candidate metadata ambiguity continues
to STOP; incomplete *ambient* visibility is the precise newly accepted
residual risk, not a universal unknown-is-safe rule.

These scoped observations alone cannot prove real Windows profile-load,
loaded-hive access, process restoration or future executability. The original
#305 candidate, one-use owner authority, strict handles, bound target PID/SID
and post-effect independent PID/HKU/profile/session/ACL proof remain unchanged.
No new B window should be created until native read-only binding is verified.

Every completed preflight records its scoped counts and displays the non-exhaustive
visibility warning before credentials. All three preflight observations and the
independent postread observation are retained in the outcome. Only the named
`process_observation` field is excluded from static baseline equality because
ambient counts can change; all original account/profile/source/ACL/authority facts
still compare exactly. The native baseline retains its original observation too.

The fixed scope projection records the exact executable/working-directory DACLs,
file-version resource, profile/source owner/ACL and source SHA/size/time accepted
by A, with the approved executable hash/time amendment. The runtime version and
signer thumbprint are separately pinned in code. Sources are original A's native
evidence checkpoint and its preserved matching #6251063570 snapshot, not old B's
expired execution authority. LF/CRLF normalization applies **only to this static
scope config**; every actual input still has its own raw SHA/size pin. Historical
records are unchanged. Altering the scope config cannot silently authorize drift.

## New human B and exact owner invocation

Only **after merge and native binding**, the human reviews the full packet and
directly posts its rendered exact typed B text on #305 using GitHub Web. This is
a deliberately narrower provenance requirement than historical relayed A/delta:
new B must have the fixed owner's numeric ID/login, `OWNER` association, `User`
type, no `performed_via_github_app`, no edits, correct issue, and creation time
inside the frozen window. App-posted owner prose, forged text, old B, a boolean
edit, a renamed proposal or a rehashed replacement is insufficient. The human
also deliberately confirms the exact packet hash locally. No GitHub comment can
dispatch the operation unattended.

The B text binds operation, packet raw SHA **and size**, plan SHA, entry SHA,
window, exact pinned invocation, allowed normal profile-load writes and residual
delayed-logon/partial-restoration risk. The packet digest transitively binds all
source pins, identities, baseline, executable/candidate bytes, paths and procedure.
No real B text, new real window or executable values are created by #310 tests.

**Future procedure only; these placeholders are not a runnable command.** In a
normal, non-elevated `WOBBUFFET\c-admin` console, set location to
`C:\WINDOWS\System32\WindowsPowerShell\v1.0`, then use the packet's pinned template:

```text
& '<powershell>' -NoProfile -ExecutionPolicy Bypass -File '<entry>' -Stage EXECUTE_EXACT_OWNER_B -PacketPath '<packet>' -ExpectedPacketSha256 <packet_sha256> -BCommentId <new_human_web_comment_id>
```

`<powershell>` is exactly `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe`;
`<entry>` and `<packet>` are the absolute pinned paths. Substitute only these bound
values, raw packet digest and the numeric ID of that new human Web B. The entry
requires this exact fresh interactive argument vector with no redirection or
profile; it rejects automatic module-pipeline logging/transcription policy.
The process-only Bypass setting matches the reviewed broker launch convention;
it writes no execution-policy registry setting and cannot override group policy.
Never start a transcript or attach a debugger/credential recorder to this process.
The entry point is **this script**, never the old JSON or the #305 candidate directly.

Immediately before the credential dialog, the entry requires all of:

- Exact A/delta body digests, new typed B, unchanged GitHub main and latest
  #305/#216/#195 records; unavailable/changed evidence stops.
- Exact actual host, broker name/SID/non-elevated token, PS5.1 x64 build, actual
  current executable, signed Microsoft subject/thumbprint, SHA/size/time/version,
  TrustedInstaller owner, executable/working-directory DACL and baseline.
- Raw candidate/entry/source/plan/packet hashes and sizes. Open read handles deny
  write/replacement/deletion of approved inputs through cleanup.
- Matching enabled non-admin target SID, ProfileList/profile/status, absent exact
  HKU SID **and SID_Classes**, zero target sessions, scoped process observation and no runner activity,
  source metadata/SHA/ACL, all 16 canonical slots and dedicated output absent,
  unchanged consumed-authority and generation metadata. No broker HKCU policy
  fallback. HKCU is consulted only for the **broker's logging policy**.
- Current host UTC inside the frozen <=600-second window, **>240 seconds remaining**
  before human input. Slow gates/dialogs cannot start a late target: every gate is
  rerun after input, with **>180 seconds** for the existing bounded supervisor and
  independent postread. The extra budget is deliberately conservative; it is not
  a promise that Windows native logon is cancellable.

After the first complete gate, a fixed operation-name `.claim` is created with
`CreateNew` and a retained handle denying writes/deletion. Two terminals/packets/
windows share this same operation key: at most one can reserve. Failure, empty or
partial reservation, cancellation, exception and success all leave the claim;
there is no deletion/reset/retry path. A pre-effect cancellation is NOT_RUN but
reserved/unusable; a human must decide any subsequent disposition. This code does
not infer consumption or global historical non-use merely from metadata absence.

Only then does the human confirm the digest and enter credentials in the native
secure dialog. Codex must never collect, enter, inspect or log them. PSCredential
stays in memory; no password/cipher/object goes into arguments, environment,
artifacts, transcript, GitHub or target stdout. The unchanged candidate uses its
private stdin envelope. A final full gate follows the dialog; credential disposal
is in `finally`. A cancelled/slow dialog cannot bypass time/authority checks.

## Containment and evidence

Invoke the unchanged candidate once, retaining its `-ExpectedPlanSha256` and
candidate SHA checks. Require every typed startup/collector/owned-exit/release /
independent PID/poststate condition, worker exit code zero, and policy observation.
After **every invocation**, including failure/malformed report/timeout, attempt a
separate normal-broker read-only child with an eight-second stdout deadline and
retained-handle cleanup. Preserve parsed candidate diagnostics, readback facts or
explicit unavailable/owned-exit status; never discard partial evidence. This
`INDEPENDENT_POSTREAD` stage cannot prompt, launch a target or grant authority, and
can read state after B expiry. It cannot clear an already uncertain startup.
Read native state independently, including SID_Classes, exact operation PID
absence, scoped process observation, profile Loaded=false, sessions=0 and account/source/profile ACLs.
Source NTUSER.DAT bytes/time/size may normally change; those fields are excluded
only from **post** comparison. ACLs and all other baseline facts remain mandatory.
Require a final in-window postread. Diagnostic evidence is written exclusively to
the packet's fixed `.handoff-result.json` under the established handoff root.

Any candidate failure/BLOCKED, startup/collector timeout, nonzero/unknown exit,
postread uncertainty or potential late logon becomes **STOP_PARTIAL_PROFILE_STATE**
once invocation begins, even if an immediate snapshot is empty. Do not retry,
force-unload, elevate, repair policy/ACL/account/service/task state, kill unrelated
processes or auto-recover. Preserve the claim and evidence for a separate human
recovery decision. A failure to persist evidence is also a stop, never success.

`DIAGNOSTIC_POLICY_OBSERVED` is diagnostic only, never `PHASE0_PASS`, reusable
freeze evidence, runner/dispatch authority or pilot PASS. General #195 remains
BLOCKED. Real native restoration and delayed-logon behavior remain unproven by
fixtures. Ready, merge and every target operation remain human-final under ADR #90.

## Non-live acceptance evidence

| Acceptance | Tests |
|---|---|
| Deterministic mapping/raw pins; false/forged flags rejected; A/delta subject/runtime/window bounds | `test_issue310_handoff.py` |
| PS5.1 parser/current UTC/reserves; fresh fake direct-owner B; missing/historic/app/forged/wrong-owner B | `test_issue310_handoff_windows.py` |
| Typed facts including unavailable HKU/profile/slots/signature/ACL; cancellation and gates before prompts | same native synthetic suite |
| Actual scoped selection: 139 unqueried unrelated owners; related/target/runner/descendant/bound-PID uncertainty; missing target facts and metadata; path boundaries; retained changing observations | same native synthetic suite, all CIM/target boundaries mocked |
| Two concurrent exclusive reservations; empty partial claim; no replay | same suite, disposable workspace files only |
| Startup/collector timeout, exit failure, unknown late logon, false success downgrade | same suite, fake diagnostic and API boundaries |
| Existing strict policy, retained handles, timeout/independent restoration and current-user pipe lease | unchanged #305, Phase0 policy/collector and Phase4 contract suites |

Exact final-head CI and independent review records belong to the Draft PR and
#310 checkpoint. Full inline-thread inventory (including outdated threads) must be
read before any human Ready/merge recommendation; resolution needs explicit owner
authorization. Test PASS alone is never live readiness.

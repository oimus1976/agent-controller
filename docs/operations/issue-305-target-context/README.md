# #305 target-context probe: owner review packet

**DESIGN / FIXTURE REVIEW ONLY. No live authority or executable handoff.**

Authority: [owner direction #6098097114](https://github.com/oimus1976/agent-controller/issues/305#issuecomment-6098097114), parent [#216](https://github.com/oimus1976/agent-controller/issues/216), MVP [#297](https://github.com/oimus1976/agent-controller/issues/297), human-final [ADR #90](https://github.com/oimus1976/agent-controller/issues/90). Base: merged main `15459e4395e7ab228e1c140b04256e569643f9b9`. Historical STOP branch `codex/issue-305-one-off-phase0` at `25712aee39c8c15421b0803f9955ac03093c04d0` is preserved; its synthetic hive loader is not imported. No #302 script, approval or authority is reused.

This single-purpose diagnostic addresses the unloaded target hive that blocks Phase 0 v3. It renders the already-supported Phase 4 `target_launch_lines` shape and embeds the **unchanged** Phase 0 `_local_probe` command. It does not change either production module or #195's general gate. The small harness costs a one-time review rather than a new reusable registry subsystem.

## Reviewed bytes

`Issue305-TargetContextProbe.ps1` is generated from `scripts/Issue305-TargetContextProbe.ps1.in` by `scripts/issue305_target_context_probe.py`. `design-plan.json` freezes its LF and CRLF SHA-256/size, exact fixed target/broker command bytes and time budgets. Python fixture assertions reproduce the reviewed files without executing them. The generator exclusively creates a new review directory/files; these are never canonical Phase 0 outputs.

| Representation | SHA-256 | Bytes |
|---|---|---:|
| Candidate Git LF | `6cd129e4bc3417694ffc1fd2791e73a585e95722619bc76f1da4656e9a4bc74a` | 32136 |
| Candidate Windows CRLF | `c135d9357f0ed82cf07fd41a6a68b3a71eeebea51899a0f51c852a543b2ec571` | 32421 |
| Fixed target command UTF-8 | `0cd1eb0cffc994cf08fca6e52792c477e918c41a8654c8a6a0177a581a050e5e` | 463 |
| Unchanged broker command UTF-8 | `81caea89d9bc3e603794cbccaad9792c1401b150a0b2b660f14caacff650adfb` | 4570 |
| Design plan Git LF | `f49e2c1e324102603516c0d2f3a3e308c7bb07351d08f8671130a178e28b2891` | 2241 |
| Design plan Windows CRLF | `8d40ac394f2b17eefa50717052c1d6195a5d047010a87811f1e478eb187bdf35` | 2312 |

A future plan must bind **actual Windows file bytes**, not infer a digest from Git. The review plan has `live_binding=null`, `decision_a=false`, `decision_b=false`; it cannot satisfy the candidate's live schema. Neither true booleans in a file nor merging this PR confer human authority. The owner must review and authorize the exact later plan independently. No live plan or invocation command is delivered here.

## One proposed future operation

1. From a normal, non-elevated `<HOST>\c-admin` Windows PowerShell **5.1 x64** broker, validate fresh exact host/full target SID, existing enabled non-admin `ac-runner`, existing profile path, trusted signed System32 PowerShell executable/hash, fixed working directory, candidate hash/size and one short UTC window. Independently establish no target session, HKU mount or Loaded profile, and baseline account/profile/source ACLs. Recheck idle state inside the launcher before target creation.
2. Start one short same-broker launcher. Send a Windows DPAPI encrypted credential envelope over its stdin and retain that pipe for the later release signal; no password, cipher, or credential object is emitted, stored, put on command lines, or sent to target stdout. The launcher decrypts only in memory and disposes its secure password. It uses `UserName/Domain/Password`, `UseShellExecute=False`, `LoadUserProfile=True`, redirected channels and the retained creation handle. No broker environment dictionary is copied into target launch arguments.
3. The trusted target command uses only fixed .NET identity/pipe operations, without profile scripts, target repository code or PowerShell module autoloading. It emits PID/full SID/name/version corroboration and waits for `RELEASE`. Its own 60-second lease and EOF rejection prevent an intentionally persistent child. The launcher checks actual owner SID/executable via a PID-filtered independent Windows observation. Target stdout is never authoritative policy evidence.
4. While the child is held, the **supervisor** runs the unchanged collector command in a fresh process with the same intended normal broker identity, retains its creation handle, and requires strict broker `HKU\exact targetSID` access. The launcher does not own or invoke that subprocess, so supervisor cancellation of the launcher cannot discard the collector's cleanup handle. Invalid/missing/unreadable hive/policy or preventing MachinePolicy/UserPolicy precedence blocks the diagnostic. No broker HKCU or target-side fallback is accepted.
5. After the collector returns or fails, supervisor sends `RELEASE` and closes launcher stdin; launcher releases target stdin, waits for actual child exit code, and, when needed, terminates only a process for which this invocation retains a creation handle. Drain/check channels and dispose handles, including failed collector teardown. Unconfirmed collector exit remains partial even when target cleanup succeeds. Fresh independent broker readback must find the reported target PID absent, HKU absent, Loaded false, no target sessions and unchanged observed account/profile/ACL baseline. A PID is used only for readback, never to select a process to kill.

Startup is supervised for 10 seconds; launcher waits at most 25 seconds for supervisor release and its final report is bounded at 15 seconds. The collector calling process is bounded at 12 seconds, owned exit waits at 5 seconds, independent readbacks at 8 seconds. Channel waits emit a fixed heartbeat. These are per-stage budgets, not an end-to-end promise including postread/cleanup.

Creation may block in native logon/profile loading. The supervised launcher bounds the parent's decision and can be terminated through its retained handle. **Killing it does not prove cancellation of an in-flight Windows logon.** Unknown creation/exit, even with an immediately empty readback, always yields `STOP_PARTIAL_PROFILE_STATE`; a delayed native completion remains possible. There is no automatic retry, unload, privilege escalation or repair. This residual condition is for the owner's explicit decision, not an asserted native success.

Allowed after both later decisions: one credential-bound fixed target child/profile load, short owned broker processes, strict read-only identity/policy/poststate observations, stdin release and retained-handle cleanup. Forbidden: direct RegLoadKey/RegUnLoadKey, elevation, policy/account/group/ACL/service/task changes, script downloads, target PR code, GitHub API mutation, freeze/canonical collection, runner registration or dispatch, persistent background process, credential logging and consumed/#302 authority reuse. Windows normal profile loading can write NTUSER.DAT and its logs: **source SHA preservation is not promised**. ACL/baseline observation does not prove file-content immutability.

## Requirements, acceptance and non-live evidence

| Requirement | Acceptance condition | Fixture evidence |
|---|---|---|
| Exact fixed bytes / review-only authority | LF/CRLF differ; design/schema match; no live binding; exclusive output | 6 portable design tests |
| Supported normal target launch | Explicit account/domain/password, profile load, trusted dir, creation handle; command fits documented 1024-character logon limit | design launch/payload tests; native PS5.1 parser |
| Correct broker policy subject | Exact SID, strict HKU reader, absence/denial/malformed values block; precedence prevents false success | exact generated broker command fixture; wrong SID/access-denied/precedence tests |
| Bounded lease and channels | RELEASE exits 0; EOF/nonzero/timeout fail; fixed heartbeat; output restrictions | actual current-user pipe fragment with 150ms fixture lease; mocked deadlines, stderr/tail tests |
| Cleanup and restoration | Supervisor retains collector handle; release/owned kill/dispose; actual exit and independent PID/profile/HKU/baseline required | broker teardown/deadline and supervisor policy-failure/unknown-collector-exit tests; restoration/PID/Loaded/HKU/ACL drift tests |
| Unknown startup cannot imply restoration | Partial/start timeout remains STOP despite empty immediate readback | supervisor timeout; start failure/partial child tests |
| Fresh decisions / target idle | Missing/false/string decisions, wrong subject/window/shape, busy/loaded/unknown target block | plan and target-idle fixtures |

Local results: **6 portable design + 14 Windows PowerShell 5.1 tests PASS**. Regression: **9 Phase 0 collector + 5 strict Windows policy + 18 Phase 4 contract tests PASS** (52 tests total). CI and exact-head independent review links/results belong to the PR/#305 checkpoint, rather than being fabricated here.

Tests parse/extract function definitions and replace process/profile boundaries with in-memory doubles. They never dot-source the candidate entry, invoke target credentials, start `ac-runner`, read its actual hive/profile, or change real policy. The only native child execution is a fixed stdin lease fragment under the test worker's own current identity, with no target credential/profile/registry operation. The generated broker policy command uses registry/profile mocks. Historical 18 tests and the non-elevated RegLoadKey 1314 result do not prove or block this distinct API path.

## Decisions and stop point

**Decision A, later:** one #195 exception for the exact reviewed commit/candidate bytes and diagnostic effect scope above. General #195 remains BLOCKED. The exception does not approve canonical Phase 0 or pilot actions.

**Decision B, separately and later:** one actual WOBBUFFET target logon/profile-load/strict broker read/cleanup/readback after fresh host, SID, profile, executable, file-byte hashes, baseline and time-window bindings. Credential entry is a human action. Unknown native access/identity/timing/restoration blocks the operation; partial state requires STOP and a separate human recovery decision. Decisions are single-use, with no retry from consumed/failed/uncertain authority.

A confirmed `DIAGNOSTIC_POLICY_OBSERVED` would demonstrate a prerequisite only. Once this diagnostic releases the child, the hive may again be absent, so **normal Phase 0 cannot simply reuse that snapshot**. The later fresh freeze and normal Phase 0 v3 need separate fresh authority and a reviewed bounded hold/collect/release operation while the same SID is mounted; that combined collection handoff is outside this candidate. Diagnostic output is never canonical `PHASE0_PASS`, pilot PASS, freeze evidence or permission to register/dispatch.

After exact-head tests/CI and independent review, stop at **DESIGN_READY_FOR_OWNER_REVIEW** (design evidence only). Current native broker HKU access, execution-policy feasibility and actual profile unload remain unproven; no live authorization is granted. Human Ready/merge and Decisions A/B remain pending. Microsoft's [CreateProcessWithLogonW documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) supplies the supported profile-load/command-length rationale, not host proof.

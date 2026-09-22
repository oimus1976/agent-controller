# Changelog

Agent Controller の意味のある設計変更・Phase 完了・安全境界の変更を記録する。

このファイルは commit log の代替ではない。細かな実装差分は Git 履歴を正とし、ここでは「何を目指し、何が変わり、どの安全境界を維持したか」を Phase 単位で残す。

## 記録方針

- 日付は、確認できる場合は merge / commit の日付を基準とする。
- Issue / PR / commit を一次情報として再構成する。
- agent の自己申告や過去チャットだけを履歴上の事実として扱わない。
- 未確認・未復元の期間は推測で補完しない。
- Draft / 未merge の試作は、採用済み実装と混同しないよう明記する。
- provider の完了表示、plan approval、artifact publication、CI、review、Controller PASS は別の事実として扱う。

---

## 2026-09-22 — Burned canonical evidence archival hardening（Issue #227 / Draft PR #228）

関連: Issue #227, Issue #216, PR #228

### Added / changed

- #216 restart時の固定canonical evidenceを、approval / protected consumption authorityを除外したstrict allowlistだけでgeneration-scoped archiveへ退避するcontroller-owned helperを追加。
- plan/apply間のsource hash・size・controller source binding、elevated Windows runtime、handle-bound source retirement、handle-relative archive creation、authoritative PASSの遅延publishをfail-closedで固定。
- external evidence-root mutation handle quiescenceを追加し、SeDebugPrivilege有効化後にpre-open handleを検査。OpenProcess / DuplicateHandleで検査不能なlive handleは見逃さずBLOCKEDとする。
- PR #228 exact-head CI #890で、quiescenceの生存確認snapshotを複数candidate間で再利用することでclosed handleをliveと誤認し得るraceを確認。初回のfresh rereadは共有しつつ、DuplicateHandleを1回だけ再試行し、その再試行も失敗した場合だけforced fresh rereadして、なおliveかつ複製不能な場合のみBLOCKEDとする修正を追加。
- user-controlled Git replacement objectによるsource authentication迂回を防ぐため、trusted Git environmentとlocal object-sensitive commandの双方でreplacement objectsを無効化。

### Safety / authority boundary

- helperはGitHub mutation、runner mutation、credential取得/利用、workflow dispatch、target execution、pilot final PASSを行わない。
- approval filesとprotected consumption markersはarchival scope外のまま維持し、burned authorityの再利用を許可しない。
- WOBBUFFET上の実archive apply、Ready、mergeはhuman-final。Draft PR上の実装・CI・reviewだけではlive effectを許可しない。

### Validation status

- prior exact head `fc3394aac602a44af94212c1b202ac0b571a4f74` / deterministic-tests #862 はSUCCESS。
- Codex rereviewでGit replacement objectsとunduplicable external mutation handleのP1 2件を受領し、後続headでremediationを継続。
- exact head `b29334b893b3c2114075600ddf2b932250fbfac8` / run #890 はLinux unittest SUCCESS、Windows lane FAILURE。failureはexternal-handle quiescenceのraceとstatic message assertionで、後続headに修正を追加。
- exact head `ce4af6027914f326c3b7010cace802fe080166bd` / run #894 ではreal external evidence-root mutation-handle regressionを含むruntime checksはPASS。残件はuninspectable-handle error wordingのstatic assertion 1件。
- exact head `f9bdc0c533ec160e47cdfa0706f33ecde10cf578` / run #896 でもruntime checksはPASSし、残件は同メッセージをsource上でsplit literalにしていたためstatic substring assertionに一致しない1件のみ。後続headでsingle literalへ修正済み。new exact-head CIで再検証する。
- PR #228はDraftのまま。human Ready / mergeおよびWOBBUFFET archive applyは未実施。

## 2026-09-19 — Phase 4/5 gated private-CI harness foundation（Issue #225 / Draft PR #226）

関連: Issue #225, Issue #216, Issue #207, Issue #195, PR #226

### Added / changed

- #216の実機pilotでPhase 3 registration PASS後にPhase 4/5のcontroller-owned live harnessが存在しないことが判明したため、Requirement -> AC -> planned testsのtraceability baselineをIssue #225へ固定。
- Phase 3 -> Phase 4 -> Phase 5で共有するcross-phase pilot bindingを追加し、repository / PR / target SHA / trusted workflow SHA+path / runner id-name-label / environment generation / runner root-work folder / host / broker identity / target identityを明示的に保持する。
- consumed済みhistorical #216 runner/generationをfuture pilotで再利用しないfresh pilot identity contractを追加。controller-owned freeze builder/CLIはGitHub/owner-machineのfresh readbackからtarget/workflow SHAを凍結し、16桁nonceからrunner name / generation / canonical runner rootを一度だけ生成する。
- successful registrationからPhase 4へ渡すsecret-free canonical registration handoffをv2へ更新。Phase 0 / registration plan / human approval / protected consumption / registration result / local runner settingsに加え、fresh generation全体のcanonical tree snapshot SHA-256をhash-chainへ含める。
- generation snapshotはgeneration root直下がcanonical `runner` 1ディレクトリだけであること、`_work`がまだ存在しないこと、symlink/reparse pointがないこと、全file path/content/sizeが凍結snapshotと一致することを検査する。Phase 4はplan時、human approval前、durable consumption後かつmutation直前にsnapshotを再検証する。
- Phase 4に独立human approval、restart-safe durable consumption、target-side `ac-runner` runtime probe、broker/provider credential isolation、durable-authority write denial、workspace/reparse/process/service/task freshness check、canonical Phase 4 evidenceを実装。
- #202のWOBBUFFET実測を正本として、target launchはcharacterized `Start-Process -Credential -LoadUserProfile -WorkingDirectory`境界を維持。同hostで失敗済みの`-UseNewEnvironment`は使用せず、target-side environment probeとPhase 5のactual `Runner.Listener.exe` owner readbackで補強する。
- Phase 5にregistration/Phase 4とは別のhuman approvalとdurable one-attempt consumptionを追加。markerをdispatch前に`CreateNew`し、timeout/transport uncertainty/malformed responseを含む失敗後のredispatchを禁止する。
- GitHub.com REST API `2026-03-10`の現行workflow-dispatch contractへ更新。旧`return_run_details` parameterを削除し、POSTのHTTP 200 responseが返すexact `workflow_run_id`だけをrun/job correlationに使用する。
- Phase 5はactual runner listener PID/owner=`WOBBUFFET\\ac-runner`、GitHub runner id/name/label唯一性、online/idle状態、prior exact workflow dispatch 0件をdispatch直前にfresh rereadする。その後exactly one POSTだけを許可し、returned run idに対してrun_attempt=1、trusted workflow SHA/path、actor/triggering actor、exactly one expected job、runner binding、expected metadata-only stepsのterminal successをauthoritativeにread backする。
- Phase 5 resultはconsole markerだけではPASSせず、real child exit、runner stdout/stderr hashes、local runner process identity、workflow run/job bindingをcanonical evidenceへ保持する。
- exact-head `01a39ca...` に対するCodex independent reviewでP1を2件受領し、remediationを実装。workflow runner-label exclusivityは行指向regexを廃止し、pinned PyYAML + duplicate-key rejectionで全workflow/jobを構造解析する。inline/quoted/merge-anchor/duplicate/list/dynamic/reusable-workflow jobを含むunsupported shapeはfail closedする。
- Phase 5はPhase 4後のtarget security-context driftを許容しない。Phase 5 durable authority consumption後、同じ`ac-runner` credential/profileでPhase 4のhash-bound security probeをlistener起動直前に再実行し、admin/high-integrity/environment/broker-credential/gh-auth/durable-authority isolationをfreshに再確認する。probe hashはcredential入力後にも再確認し、controller側もresultを独立parseしてprobe/result/stdout/stderr hashesをcanonical Phase 5 evidenceへ記録する。

### Safety / authority boundary

- handoff/result JSONはevidenceであり、それ自体を再利用可能なauthorityとして扱わない。Phase 4/5のlive effectは各専用human approval + protected durable consumption + authenticated AST/effect gateをすべて通る必要がある。
- registration approvalはPhase 4/5を許可せず、Phase 4 approvalはPhase 5 dispatchを許可しない。失敗・timeout・unknown state・process restart後に同じconsumed authorityを復活させない。
- current #216 historical runner/generation/Phase0/plan/approval/consumptionは再利用禁止。#225 merge後の#216 pilotはcontroller-owned fresh freezeからPhase 0-5を新規authority chainでやり直す。
- #225は`SELF_HOSTED_PRIVATE_CI_PASS`を発行しない。Phase 6 cleanup + Phase 7 zero residualを含むfinal pilot classificationは#216の責務。
- public `agent-controller`はGitHub-hosted onlyのまま。Ready / merge / destructive cleanup / live dispatch / target executionはADR #90によりhuman-final。

### Validation status

- Initial RED run #617からRequirement/ACごとのRED -> implementationを継続。
- Phase 5 API/authority/runtime実装後、run #735でLinux deterministic suiteとWindows PowerShell 5.1 AST / Phase 4 / Phase 5 candidate / authority regressionsがSUCCESS。
- generation snapshot追加後のrun #749ではWindows laneはSUCCESS、LinuxはPath concrete-type判定だけがREDとなり、`isinstance(..., Path)`へ修正済み。
- exact-head `01a39ca2c1fc97c7e1804d7131d67e0941923b47` / run #774 はLinux/WindowsともSUCCESS。そのheadへのCodex independent reviewでP1 2件（workflow YAML runner-label exclusivity、Phase 5 pre-launch target security revalidation）を受領した。
- P1 remediation後のexact head `ad741ef4c20a8d610687256633fadb3e413fa197` / run #800 はLinux/WindowsともSUCCESS。review threadへ修正根拠を返信済み。追加の記録更新後にnew exact-head CIとCodex rereviewを行う。
- PR #226はDraftのまま。human Ready / mergeは未実施で、#216 live pilotは再開していない。

---
## 2026-09-19 — Real Actions Runner `.runner` schema contract（Issue #223）

関連: Issue #223, Issue #216, Issue #221, PR #222

### Added / changed

- #216の2回目のhuman-authorized live registrationで、`config.cmd`がexit 0かつ`Runner successfully added` / `Settings Saved.`を返した後、`runner_readback_attempts=0`のままgeneric `RUNNER_READBACK_FAILED`となった実機事象を根拠にlocal `.runner` validation contractを修正。
- owner-machine read-only characterizationでActions Runner 2.337.0が生成した実ファイルを確認し、authoritative keysが`agentName` / `workFolder` / `ephemeral` / `disableUpdate`のlower camelCaseであることを確定。従来runtimeとdeterministic testsは存在しないPascalCase `AgentName` / `WorkFolder` / `Ephemeral` / `DisableUpdate`を相互に正当化していた。
- runtime validatorを実schemaへ合わせ、wrong name / wrong work folder / non-ephemeral / disable-update missingのfail-closed invariantは維持。
- runtime test fixturesを実schemaへ更新し、旧PascalCase fixtureが再び正当なrunner stateとして通らないregressionを追加。

### Safety / authority boundary

- remote runner stabilization (#221) のbounded retry / wall-clock / attempt evidence contractは変更しない。
- consumed #216 plan/approvalの再利用やregistration retryを許可しない。次回live pilotにはremote runner id 22とlocal generationのhuman-authorized cleanup、merge後のfresh Phase 0 / plan / human approvalが必要。
- Ready / mergeはADR #90によりhuman-finalのまま。

### Validation status

- このentryはIssue #223 Draft実装の一部。exact-head CIとindependent rereviewが完了するまでhuman Ready judgmentへ進まない。

---

## 2026-09-19 — Bounded post-registration runner readback stabilization（Issue #221）

関連: Issue #221, Issue #216, Issue #219, PR #220, Issue #195

### Added / changed

- first human-authorized private-CI live registrationで、registration child exit 0の後に`RUNNER_READBACK_FAILED`となり、fresh reconciliationではexact runner registrationが確認できた実機事象を受け、post-registration runner readbackにbounded stabilizationを追加。
- strict two-sweep primitive `read_all_runner_items()` は弱めず、sweep間runner set変化だけをtyped transientとして識別する。
- post-registrationでは最大6 attempt、1秒間隔に加え、remote readback全体へ15秒のmonotonic wall-clock deadlineを設定する。各`gh api` subprocessにも残り時間をtimeoutとして渡し、delay合計も最大5秒に限定する。deadlineはstrict snapshot完了後とacceptance-time local binding再検証後にも再確認し、期限後のREGISTEREDを禁止する。
- `runner_readback_attempts`は最初のremote requestを実際に開始する境界でのみ加算し、deadline切れでAPIを開始しなかったiterationを証跡上のattemptに数えない。
- retry対象は、(1) sweep間set変化、(2) stable snapshotだがfrozen runnerがまだ見えない場合のみ。duplicate eligible runner、wrong name/label、malformed/pagination異常などは即fail closedし、registration/token/configを再実行しない。
- remote exact snapshotをacceptする直前にlocal `.runner` binding（name / work folder / ephemeral / DisableUpdate）を再検証し、stabilization中のlocal driftをfail closedする。stable snapshot全体はexact eligible runner 1件へ縮約してreadbackを構築し、その構築後にfinal deadline checkを行うことで、大規模snapshot変換や後段scanがdeadline後のREGISTEREDを生まないようにする。
- bounded exhaustionを`RUNNER_READBACK_STABILIZATION_EXHAUSTED` / `RUNNER_VISIBILITY_STABILIZATION_EXHAUSTED`として既存`RUNNER_READBACK_FAILED`に追加記録する。
- live result schemaをv2へ更新し、`runner_readback_attempts`をresult/transcriptへ記録して、実際に何回read-only stabilizationしたかを監査可能にする。

### Safety / authority boundary

- stabilization loopはread-onlyであり、registration credential取得・runner config・workflow dispatch・target executionを含まない。
- consumed human authorizationに対するregistration mutationはexactly-onceのままで、readback uncertaintyを理由に自動再登録しない。
- stable snapshot primitive自体のfail-closed structural validationは維持する。
- #216の既存live attemptはFAILのままで、#219/#220のmergeおよび本修正だけでは再pilotを許可しない。次回live mutationにはfresh Phase 0 / plan / human authorizationが必要。

### Validation status

- このentryはIssue #221 Draft実装の一部。exact-head CIとindependent rereviewが完了するまでhuman Ready judgmentへ進まない。

---

## 2026-09-19 — Windows native-output decoding hardening after live pilot failure（Issue #219）

関連: Issue #219, Issue #216, Issue #207, Issue #195

### Added / changed

- #216のfirst human-authorized private-CI live registrationで、runner登録child自体はexit 0かつGitHub/local runner identityも一致した一方、post-registration readbackが`UnicodeDecodeError`でfail closedした実機事象を根拠に、Windows native process output captureをbytes-firstへ変更。
- UTF-8 strict decodeを優先し、失敗時のみWindows preferred encodingへstrict fallbackする。どちらでもdecodeできないbyte列は明示的uncertaintyとして扱う。
- Ready後Codex reviewで判明したCP932 multibyte境界のtoken-redaction bypassを受け、registration tokenはnative outputのraw bytes段階でdecoderより先に検出・置換し、その検出事実を別フラグで保持して必ずFAILEDへ分類する。decode後の文字列redactionもdefense in depthとして維持する。
- registration childのnative output decodeがuncertainでもchild exit codeを保持し、remote runner mutationが観測された場合はそのrunner idを記録したFAILED resultを返す。registrationの自動retryは行わない。
- CP932 fallback、完全にundecodableなnative output、decode uncertainty後のobserved mutation / no-retryを回帰テストへ追加。

### Safety / authority boundary

- decode fallbackはreplacement decodeで成功扱いにしない。UTF-8 / preferred encodingのどちらでもstrict decodeできない場合はauthoritative PASSへ進めない。
- registration tokenのargv非露出・durable evidence非記録・output redaction境界を維持する。
- #216の2026-09-19 live attemptはFAILのままで、zero-residual safety cleanup完了後も`SELF_HOSTED_PRIVATE_CI_PASS`へ再分類しない。
- 本修正は新しいlive pilot authorizationを与えない。次回live mutationはfresh Phase 0 / deterministic gate / human authorizationを改めて必要とする。

### Validation status

- このentryはIssue #219 Draft実装の一部。exact-head CIとindependent rereviewが完了するまでhuman Ready judgmentへ進まない。

---

## 2026-09-18 — Mutation-time live-registration harness（Issue #217 / Draft PR #218）

関連: Issue #217, Draft PR #218, Issue #216, ADR #90

### Added / changed

- first #216 private-CI pilot向けに、exact canonical planへ結び付いたelevated human approval artifactと、administrator-protectedなone-time consumption markerを導入。
- live mutation境界でexact host / broker / frozen targetを再検証し、非injectableなfrozen-target revalidationをrunner準備前とregistration token取得直前の双方で実施。
- GitHub runner readbackを、2回のcomplete sweepが同一runner setを返すことを要求するstable snapshotに変更し、frozen runner nameまたはscheduler labelのどちらか一方でもcollisionとしてfail closed。
- registration child完了後のmutation reconciliationをboundedに行い、child failure、観測済みremote mutation、readback uncertaintyを区別してauthoritative evidenceへ記録。
- one-time registration tokenをargv・transcript・durable evidenceへ残さないsecrecy boundaryを維持し、runner packageをversionとSHA-256でpinしたfresh ephemeral runner preparationに限定。

### Safety / authority boundary

- このentryおよびPR #218はDraft / 未mergeであり、それ自体ではreal runner registrationもfirst #216 pilotも実行しない。
- harnessはworkflow dispatchとtarget repository code executionを行わない。real credential acquisition、runner registration、pilot executionはこの変更の境界外。
- Ready / mergeの判断はADR #90に従いhuman-finalのまま。

### Validation status

- prior implementation head `932d0e890a1111c60233309b81ee30d1ac6e7daa` でdeterministic-tests #581はSUCCESSし、同exact headに対するclean Codex rereviewでmaterial issueなし。
- このCHANGELOG追加はdoc-onlyの新commitになるため、新しいexact headに対するfresh CIとfinal Codex rereviewを完了するまでhuman Ready judgmentへ進まない。

---

## 2026-09-14 — Public publication: retire self-hosted exact-head fallback

Related: Issue #196

### Changed

- removed the private-era `self-hosted-exact-head` GitHub Actions workflow from the publication candidate;
- retired the implementation-specific self-hosted workflow regression suite and replaced it with a publication regression that rejects any active `self-hosted` / `ac-ci-*` runner path;
- converted the self-hosted runbook into a historical retirement record;
- narrowed the remaining public-readiness path to exact-head validation/review, merge, refreshed publication inventory, the human visibility gate, and post-public protection/hosted-CI verification.

### Boundary

- PR #193 implementation remains isolated and is not modified by this change;
- historical self-hosted design/evidence remains in Git history;
- Ready, merge, repository visibility, history rewrite, and destructive cleanup remain human-final.

---
## 2026-09-14 — Alternate-user launch environment repair（Issue #202 / Draft candidate）

関連: Issue #202, PR #193, Issue #201

### Added / changed

- fresh standard-user characterization on Windows PowerShell 5.1 confirmed that `Start-Process -Credential` with explicit `-WorkingDirectory` launches under the target SID with target-user `PATH` / `TEMP` / `TMP` / `USERPROFILE`, while synthetic parent `GITHUB_*`, `GH_TOKEN`, and GitHub command-file environment variables are absent.
- the same alternate-credential launch with `-LoadUserProfile` remained successful and isolated.
- adding `-UseNewEnvironment` caused exit `-65536` before target payload execution, with or without `-LoadUserProfile`.
- self-hosted fallback target launch therefore removes only `-UseNewEnvironment`; `-Credential`, `-LoadUserProfile`, explicit workspace `-WorkingDirectory`, and target `-NoProfile` remain.
- focused regression rejects any reintroduction of `-UseNewEnvironment` and keeps the target-side forbidden-environment and command-file negative checks.

### Safety / authority boundary

- no silent environment sanitization is added. The target still fails closed if `GITHUB_*` or `GH_TOKEN` appears, so a future launch-boundary regression cannot be hidden by cleanup.
- runner command-file paths remain trusted-parent probe literals and target write access must still fail.
- control/target SIDs, checkout ACL boundary, one-time credential deletion contract, human-final Ready/merge authority, and PR #193 implementation remain unchanged.
- no new real PR #193 pilot is allowed until Issue #202 is merged and a fresh nonce/SID/ephemeral runner is provisioned.

### Validation status

- this entry describes a Draft candidate until exact-head local validation and independent review complete; it does not claim adoption on `main`.

---

## 2026-09-13 — One-time credential deletion contract repair（Issue #201 / Draft PR #204）

関連: Issue #201, Draft PR #204, Issue #202, Draft PR #193

### Added / changed

- real self-hosted pilotで、`ac-runner` が one-time target credential を読取後に `Remove-Item -Force` で削除しようとした箇所が access denied で停止した事象を、Issue #201の独立workstreamとして修正。
- pilot相当の実機characterizationで、credential fileに `Read + Delete + Synchronize`、親directoryに delete-child権限なしという既存の最小authority境界を再現し、plain `Remove-Item` と `[IO.File]::Delete()` は成功、`Remove-Item -Force` のみ失敗する `FORCE_ONLY_FAILURE` を確認。
- workflowのcredential削除を plain `Remove-Item -LiteralPath $credentialFile` に限定し、削除後の `Test-Path` absence checkを維持。削除失敗時はtarget launch前にfail closedする。
- regression testでcredential削除commandのplain formを拘束し、`-Force`再導入と削除失敗時のlaunch到達を拒否。
- runbookに実機characterization結果と、shared credential directoryのwrite/delete-child authorityを広げない方針を記録。

### Safety / authority boundary

- credential fileの既存authority（`Read + Delete + Synchronize`）を維持し、shared parent directoryへのwrite/delete-child権限は追加しない。
- target SIDへのcredential accessは追加しない。characterizationではtarget read、protected sibling delete/write/replace、parent file createがすべてBLOCKされた。
- PR #193の実装は変更しない。`-UseNewEnvironment` によるalternate-user launch問題はIssue #202へ分離。
- Ready / mergeはADR #90に従いhuman-finalのまま。

### Validation status

- code/test/runbook head `eb652f7e2327a9868f22c65ca4697e42e82ff281` で、changed-file scope、focused workflow/ACL regressions、full deterministic suite、Windows junction regression、exact-HEAD保持、clean-tree postconditionがPASS。
- 同headに対するCodex exact-head reviewはmajor issueなし、inline review thread 0。
- このCHANGELOG追加はdoc-onlyの新commitになるため、新headに対するexact-head validationとCodex rereviewを完了するまで、上記prior-head evidenceを最終証拠として流用しない。
- この項目はDraft PR #204の未merge状態を記録し、mainへの採用済み状態を意味しない。

---

## 2026-09-13 — Public repository readiness audit / hosted CI hardening（Issue #196 / Draft PR #203）

関連: Issue #196, Draft PR #203, Issue #201, Issue #202

### Added / changed

- private repository を public へ変更するための repository-local publication contract として `docs/PUBLIC_REPOSITORY_READINESS.md` を追加。
- normal hosted CI の `actions/checkout` を pinned SHA のまま `persist-credentials: false` に固定し、`contents: read` を維持。全 hosted checkout block が credential persistence を無効化することを deterministic regression で保護。
- README に project purpose、active development status、validation command、trust boundary、public-readiness document、MIT License を明示。
- publication audit の bound main を `98d4bb9d9c8396c89c3be7b235a04dd4348e3a03` とし、authenticated mirror を `fetch=0` / `fsck=0` で確認。157 refs（うち76 PR refs）、707 commits を inventory。
- Gitleaks 8.30.1 の full-history scan で5件の `generic-api-key` finding を検出したが、全件を Ed25519 public fixture key と個別確認し、unresolved secret finding 0、history rewrite 不要と判定。
- author/committer identity inventory は707 commits 全件を対象とし、owner / GitHub / Jules bot の期待された identity のみを確認。historical owner Gmail metadata は明示的な human publication decision により受容。
- historical filename/path/blob audit は245 unique paths、secret-like path 0、machine/infrastructure identifier path 0、binary/archive/database path 0 を確認。
- retained Actions artifact は fresh inventory 8件（review artifact 7 + package-lock 1）を全件確認し、credential/private-key publication blocker 0。
- Actions run inventory は479 runs / 5 workflow files を全件取得。430 runs の取得可能な log body を private-key marker / common token-key-secret pattern で走査し candidate run 0 / match group 0。残る49 runs は98 hosted jobs（49 `unittest` + 49 `windows-junction`）すべて runner assignment / workflow step execution 前に終了しており、log body 自体が生成されていないことを確認。
- self-hosted `workflow_dispatch` 2 runs は full log を個別確認し、GitHub auth は masked、one-time password content は未出力。historical machine/runner/SID/nonce/path metadata の実値露出は既存 non-secret infrastructure diagnostics として human decision により受容。

### Safety / authority boundary

- historical non-secret identity/infrastructure metadata の受容は、secret、credential、private key、unrelated personal data の受容を意味しない。
- 新たに durable/public-facing evidence を書く場合は、不要な実機値を `<HOST>` / `<CONTROL_SID>` / `<TARGET_SID>` / `<RUNNER>` / `<NONCE>` / `<WORKSPACE>` / `<CREDENTIAL_ROOT>` 等へ正規化する。commit SHA、Issue/PR/run ID、workflow name、result、failure boundary 等の audit fact は必要に応じて exact に保持する。
- repository visibility change、Ready、merge、history rewrite、destructive cleanup はこの change では行わず、human-final authority を維持。
- human decision により MIT License を選択し、root `LICENSE` を追加。copyright holder は GitHub 公開アカウント名 `oimus1976` とした。
- public repository に bare-metal self-hosted runner を露出しないことを publication blocker として維持。fallback は publication 前に retire/disable するか、#201/#202 および failure/cancellation cleanup contract を含めて remediation + re-verification が必要。
- private-plan capacity block により hosted exact-head CI が runner assignment 前に停止する場合、それを implementation PASS/FAIL とみなさない。public 化後に canonical hosted jobs が実際に GitHub-hosted runner 上で開始・完走することを post-public verification で証明する。
- visibility change 後、`main` protection/ruleset を即時設定して read back するまで publication closeout としない。

### Validation status

- `docs/PUBLIC_REPOSITORY_READINESS.md` は full-history / identity / path / retained artifact / Actions log audit の completed evidence と残る blockers に同期済み。
- prior docs-synchronized head `e0051b6fe638c94ef094d2f56763985cfaa8cc2c` に対する run `34745313182` は `unittest` / `windows-junction` とも `steps=null` で runner execution 前に failure。`HOSTED_CI_NOT_EXECUTED / PRIVATE_CAPACITY_BLOCKED` と分類し、implementation test failure / PASS のいずれにも数えない。
- この項目は Draft PR #203 の未merge状態を記録する。license gate は MIT 選択と root `LICENSE` 追加により完了。最終 Ready gate は self-hosted posture の解決、current exact-head local validation、independent review、および human judgment を要求する。

---

## 2026-08-30 — Codex request amplification observation（Issue #113 / Draft PR #114）

関連: Issue #55, Issue #113, Draft PR #114

### Added / changed

- GitHub-authoritative issue comment / PR review evidenceから、trusted exact-head `@codex review` request、trusted source-head `@codex address that feedback` request、Codex review submissionのexact `commit_id`をread-onlyに集計するobservationを追加。
- serial multi-head review/remediation loopとsame-head duplicate replayを分離し、distinct reviewed heads、distinct loop heads、per-head counts、duplicate countsをconcise JSONで出力する。
- standalone read-only CLI `python -m agent_controller.codex_amplification --repo OWNER/REPO --pr N --policy PATH` を追加し、既存policyの `trusted_review_request_authors` を再利用する。
- malformed / ambiguous GitHub evidenceは `UNCERTAIN` にfail closedし、推測で補完しない。

### Efficiency / authority boundary

- GitHub request数はprovider turn、token、5-hour/weekly allowance、costではない。`provider_turn_count`、token fields、allowance unitsはauthoritative provider/account telemetryがない限りUNKNOWNのままとする。
- UI scraping、interactive `/status` parsing、token estimation、automatic throttling/model downgrade/provider routing/review skippingを追加しない。
- provider write、remediation/review trigger、Ready、merge、Update-branch automationを追加しない。read-only observationのみ。
- PR #112-shaped regression fixtureでserial amplificationとsame-head duplicatesを分離し、deterministic suiteで検証する。
- この項目はDraft PR #114の未merge実装を記録しており、mainへの採用済み状態を意味しない。

---

## 2026-08-29 — Bounded Codex remediation request（Issue #111 / Draft PR #112）

関連: ADR Issue #12, ADR Issue #90, Issue #111, Draft PR #112

### Added / changed

- unresolvedなtrusted Codex findingに対し、固定本文 `@codex address that feedback` だけを投稿するbounded action `REQUEST_CODEX_REMEDIATION` を追加。arbitrary prompt/comment capabilityは公開しない。
- 実行gateをDraft/open/unmerged PR、明示的なnon-base implementation branch、exact current head、exact-head Actions `PASS`、safe scope `SATISFIED`、current-headのunresolved trusted Codex findingに限定。old-head findingやstale evidenceはauthorizationに使用しない。
- authenticated posting identityのallowlist確認後、POST直前にcurrent-headのunresolved trusted Codex finding、head/state/Draft/base ref/repository/commit SHA、policy、およびexact-head Actions `PASS`をfreshに再検証し、計画時のauthorization evidenceから変化していればwriteせずfail closedする。fresh evidence sweep前のbase driftもcallerの元planに対して検出する。threadはroot commentがCodex由来の場合だけCodex findingとし、originating reviewと関連付け、dismissed reviewのthreadはauthorizationから除外する。resolved Codex threadが残すstaleな`CHANGES_REQUESTED` review stateはそのthreadのoriginating reviewに限ってunresolved findingとして扱わず、unrelated threadや別reviewのthreadはreview-level fallbackを抑止しない。
- request publicationのpostconditionは、固定remediation request markerが公開されたことと、その公開後にfreshに再読したPR snapshotがauthorization対象のhead/base/repository/Draft/open targetと一致し続けることの両方を証明する。再読のuncertaintyまたはdrift検出を`REQUEST_PUBLISHED` / `PASS`として報告しない。ただしremediation成功、finding解消、code trust、review approvalを意味しない。
- trustedなsame-source-head markerによりretry/replay/serial requestをdedupeする。ただしGitHub comment creationにdistributed atomic claimはなく、真に同時の複数instanceに対するglobal exactly-onceは保証しない。

### Observed Codex Cloud boundary

- live observationでは、Codex Cloudを利用するにはrepository environmentの作成が必要だった。またCodexが変更を生成した後も、GitHub上のPR headを変更するには独立したbranch-publication step（`Update branch`）が必要であり、remediation requestの投稿やCloud task完了だけではGitHub headは更新されない。
- publication後のresulting codeもuntrustedな新しいcandidateであり、更新されたexact headに対するCI、scope検証、independent reviewへ再投入する。以前のheadに対するevidenceを流用しない。

### Authority / safety boundary

- auto thread resolution、automatic retry/polling、local model turn、Ready、mergeは追加しない。request publication後のfinding状態やbranch publicationをControllerが成功として推定しない。
- Ready / mergeはADR #90に従いhuman-finalのまま。この項目はDraft PR #112の未merge実装を記録しており、mainへの採用済み状態を意味しない。

---

## 2026-08-28 — Exact-head Codex review request（Issue #109 / Draft PR #110）

関連: ADR Issue #12, ADR Issue #90, Issue #55, Issue #109, Draft PR #110

### Added / changed

- repositoryで既に利用しているCodex GitHub integrationの `@codex review` triggerを再利用し、current PR headに対する独立review要求をControllerから行うbounded action `REQUEST_CODEX_REVIEW` を追加。
- `request-codex-review` CLIを追加し、明示policy allowlist、Draft/open PR、exact current head、exact-head Actions `PASS`、safe scope `SATISFIED`、current-head review/request不存在を満たす場合だけ実行可能にする。
- comment write capabilityは汎用化せず、固定本文 `@codex review` と deterministicな不可視exact-head markerだけを投稿する専用mutatorに限定。
- apply直前にpolicyとGitHub evidenceをfreshに再読し、head/state/CI/scope/review evidenceが変化した場合はwriteせずBLOCKED/NOOPへ落とす。
- same-head markerまたはcurrent-head Codex review evidenceがGitHubに存在する場合、再実行・後続別instanceはNOOPとしてreview quotaの重複消費を抑制する。
- PR #107 reviewで見つかったrename/malformed changed-file classを再導入しないよう、新actionはlegacy `inspect_pr.scope_status`をauthorityにせず、raw GitHub filesを検証し `previous_filename` を含むsource/destination双方をscope評価する。

### Safety / efficiency boundary

- Codex review requestはコード承認・Controller PASS・Ready/merge authorizationではない。human-final境界はADR #90のまま。
- Codex local SDK/model turn、provider dispatch、Ready、merge、auto-merge、workflow dispatch/re-run、deploy/releaseは追加しない。
- arbitrary PR comment capabilityを公開せず、review trigger以外の本文をcallerから注入できない。
- GitHub comment creationには「same-head markerが存在しない」こととのatomic compare-and-setがないため、**global exactly-onceは主張しない**。2 Controller、またはreview結果到着とrequest writeが完全同時に競合すると、同一headへ重複review要求が発生し得る。
- marker/review evidenceがGitHubへ反映された後のretry/replay/serial cross-instance runはdeterministicにdedupeする。完全同時raceの残余効果はreview/quota重複に限定され、Ready/merge等のauthorityへ昇格しない。
- このbounded raceだけを消すためのdistributed lock/claim serviceは、実運用で痛みが確認されるまで導入しない。
- token数は推定・捏造せず、review requestの存在とhead bindingをGitHub evidenceとして扱う。

### Validation status

- deterministic testsでpolicy/PR state/exact-head CI/scope/review evidence gates、old-head vs current-head semantics、fixed comment surface、pre-write stale detection、policy revocation、postcondition、replay dedupeを検証する。
- concurrency testは同じpre-write snapshotを同時に見た2 instanceが双方EXECUTABLEになり得ることを意図的に固定し、このsliceがdistributed exactly-onceを保証しないことを契約化する。
- self-reviewで、PR #107のsafe rename normalizationが`objective_target.py`のprivate pathに閉じ、legacy `inspect_pr.scope_status`には波及していないことを検出。新review-request経路ではraw filesを独立にsafe normalizeしてから既存`evaluate_scope()`へ渡すよう修正。
- initial deterministic CI #186は391 tests中1件失敗。pre-write policy revocationでGitHub headを未読のまま`None`を`STALE_HEAD_SHA`と誤分類していたため、「fresh headを実際に観測した場合だけstale判定する」よう修正し、次headのCI #187はSUCCESS。
- この項目はDraft PR #110の未merge実装を記録しており、mainへの採用済み状態を意味しない。
- final merge gateはCHANGELOG反映後のexact-head deterministic CIと、同headへのindependent Codex review。Ready / mergeはhuman-final。

---

## 2026-08-28 — Objective GitHub target verification after live Codex completion（Issue #106 / Draft PR #107）

関連: ADR Issue #12, ADR Issue #90, Issue #55, Issue #91, Issue #106, Draft PR #107

### Added / changed

- live Codex の terminal `ARTIFACT_READY` + `SUCCESS` を、成果物の成功証明ではなく **objective GitHub verification を開始する trigger** として利用する one-shot composition を追加。
- Controller が明示的に保持する `GitHubTargetExpectation(repo, ref)` と、GitHub fresh read から得る `ObjectiveGitHubTargetEvidence` を分離。
- explicit branch ref を GitHub から fresh resolve し、immutable candidate SHA、`expected_start_sha` からの ancestry、changed-file scope を独立検証する read-only 経路を追加。
- GitHub evidence に `github_observed_at` を保持し、point-in-time の objective evidence として freshness / audit の基礎を残す。
- `verify-codex-target` CLI を追加し、PR #105 の disposable Codex snapshot observation と objective GitHub target verification を接続。
- GitHub read adapter は既存 authenticated GET transport を再利用し、branch ref / compare の read-only surface のみに限定。
- GitHub compare の changed-file set が 300 件に達する場合は truncation の可能性を理由に scope PASS を推定せず fail closed。

### Authority / safety boundary

- `ArtifactEvidence.provider_reported_ref` / `provider_reported_sha` に Controller 設定値を偽装して流用しない。
- Codex assistant prose、command output、item content、thread `gitInfo` は final GitHub artifact identity の authority としない。
- target identity は Controller-owned task/config input、resolved SHA / ancestry / scope は GitHub-owned objective facts として区別する。
- provider terminal success だけでは Controller PASS にしない。provider completion後も GitHub target が unchanged / divergent / scope violation / malformed / unavailable なら PASS しない。
- provider observation / binding が不整合・malformed・unavailable の場合、GitHub verification を開始せず BLOCKED / UNCERTAIN に fail closed。
- source Codex home isolation、approval reject、finite timeout、SDK pin、unknown-status fail-closed は PR #105 の境界を維持する。
- provider dispatch / continued turn / remediation、GitHub write、review trigger、Ready、merge、auto-merge、workflow dispatch、release / deploy は追加しない。
- Ready / merge は ADR #90 に従い human-final のまま。

### Validation status

- deterministic testsで terminal provider success が必要条件だが十分条件ではないこと、Controller explicit target が provider `gitInfo` より優先されること、unchanged / divergent / scope violation / read failure / malformed observation が PASS しないことを検証する。
- self-review で初期実装の GitHub evidence に観測時刻がない freshness / audit 欠落を検出し、`github_observed_at` を追加して修正。
- exact-head `efa94a0904217f67fdc6ecbf329ac46b6278ff4b` のCodex reviewで、rename時に`previous_filename`をscope判定していないP1と、malformed changed-file entryがdenied-only policyでPASSし得るP2を検出。
- P1/P2は、GitHub changed-file entryの`filename` / `changes` / 任意`previous_filename`をscope評価前に検証し、renameのsource/destination双方を既存`evaluate_scope()`へ渡すよう修正。denied sourceからallowed destinationへのrenameとmalformed entryの回帰テストを追加。
- この項目は Draft PR #107 の未merge実装を記録しており、mainへの採用済み状態を意味しない。
- final merge gate は review remediation反映後の exact-head deterministic CI と exact-head independent re-review。Ready / merge は human-final。

---

## 2026-08-27 — Codex observation source-home isolation（Issue #104 / Draft）

関連: ADR Issue #12, ADR Issue #90, Issue #102, PR #103, Issue #104

### Safety-boundary correction

- PR #103 merge 後の Windows 実機 negative smoke で、公式 app-server に送った provider RPC が `thread/read` だけでも、app-server 起動時に `CODEX_HOME` へ `installation_id`、SQLite state/log/memory/queue DB、system skills、temporary helper files 等が作成されることを確認。
- したがって、PR #103 でいう「read-only」は **provider lifecycle / model turn / approval / task mutation を行わない**という意味では維持されるが、**owner-machine / local filesystem write-free** を意味しない。以前の表現をこの点で訂正する。
- exact upstream `0.147.0` を確認した結果、app-server startup の state persistence を無効化する公式 read-only / non-persistent mode は見つからなかった。`installation_id` は起動時に read+write+create で開かれ、state runtime も初期化/backfill される。
- このため、実ユーザーの Codex Desktop / CLI `CODEX_HOME` を app-server に直接渡す運用を禁止し、positive real-thread smoke も source-home isolation 実装まで停止した。

### Draft implementation

- `CodexOfficialSdkReadClient` は app-server のローカル書込み先となる **明示的な absolute `codex_home`** を必須化し、継承/defaultの `CODEX_HOME` に依存しないよう変更。
- 公式 Python SDK の `CodexConfig.env` を使い、app-server 子プロセスにのみ disposable `CODEX_HOME` を注入する。
- 新しい `CodexSnapshotReadClient` は、明示した source Codex home から対象threadの persisted rolloutだけを検索し、一時 `CODEX_HOME` へ相対pathを保ってコピーしてから公式 `thread/read` を実行する。
- source home の `state_*.sqlite`、WAL/SHM、installation state、skills、その他threadは snapshotへコピーしない。app-serverが必要とするDB/backfillは disposable snapshot側だけで生成させる。
- rolloutは `sessions/` / `archived_sessions/` 配下の canonical UUID に一致する単一 `.jsonl` または `.jsonl.zst` に限定。missing / ambiguous / symlink / source-home外へのpath escape は fail closed。
- source rolloutを copy前・copy後・観測後に SHA-256 で照合し、copy mismatch または観測中のsource変更を stale evidence としてfail closedする。
- `observe-codex` CLI は `--source-codex-home` を必須化し、ユーザー向け経路を `CodexSnapshotReadClient` のみに変更。source homeそのものをSDK/app-serverへ渡す直接経路をCLIから除外。

### Safety / trust boundary

- `provider_read_only` と `owner_machine_write_free` を別の性質として扱う。公式 app-server のstartup writeは disposable Controller-owned pathのみに閉じ込める。
- source Codex homeはController自身が対象rolloutをread/hash/copyするだけで、公式 app-server processには渡さない。
- snapshotは evidence-at-copy-time として扱い、source evidenceが観測中に変化した場合は成功を推定しない。
- provider completionは引き続き `ARTIFACT_READY` / terminal claimまでで、Controller `PASS` ではない。
- approval handler reject、SDK version pin、timeout、unknown-status fail-closed、LEVEL 3 human-finalはPR #103の境界を維持する。

### Validation status

- deterministic testsを追加し、target rolloutのみのcopy、source DB/other rollout非copy、disposable SDK home、plain/compressed rollout、ambiguous/missing/invalid ID、観測中source変更のfail-closed、CLIのsnapshot-only routingを検証する。
- この項目は Issue #104 の Draft 実装を記録しており、mainへの採用済み状態を意味しない。
- initial Codex reviewで、snapshot parentがsource home配下へ解決される場合にapp-server startup writeが実homeへ戻り得るP1を検出した。
- P1は、effective temp parentをTemporaryDirectory作成前にresolveし、source homeと同一・配下・symlink経由・default temp経由のoverlapをSDK起動前にfail closedするよう修正。exact-head `0769b4607a9f13824a643da0086055e846e9998f` のCodex re-reviewでmajor issueなしを確認し、review threadをresolvedとした。
- 同code treeをWindows実機で deterministic suite 335 tests 実行し、全件OKを確認した。
- merge gateとしてfinal exact-head CI、final exact-head independent review、positive real-thread smokeを要求し、prior-head evidenceから成功を推定しない。Ready / merge はADR #90に従いhuman-finalのまま。

---

## 2026-08-27 — Live Codex read-only observation（Draft PR #103）

関連: ADR Issue #12, ADR Issue #90, Issue #102, Draft PR #103

### Added / changed

- 既存の `ProviderReadClient -> CodexObservationAdapter -> map_codex_observation()` 経路へ、実Codex threadを一回だけ読む `CodexOfficialSdkReadClient` を追加。
- 当初検討した bespoke stdio / JSON-RPC transport は採用せず、公式 `openai-codex` Python package 内の app-server client と typed `thread_read()` を再利用。
- `observe-codex --thread-id ...` を追加し、既存thread IDを明示して一回だけ観測できるCLI境界を追加。
- optional live-provider dependency を `requirements-codex.txt` に `openai-codex==0.147.0` として固定。低レベルapp-server client依存のversion driftはfail closedする。
- optional `--codex-bin` で明示的なCodex executable pathを指定可能。未指定時は公式SDKがbundled/resolved runtimeを選ぶ。
- official `thread/read` responseからprovider prose/item contentを保持せず、thread/turn statusとopaque thread IDだけを既存mapper vocabularyへ投影。
- finite Controller-side timeoutを追加。upstream low-level request waiterが無期限に待つ場合はofficial clientをcloseしてfail closedする。

### Safety / trust boundary

- `thread.status` は既知の `notLoaded` / `idle` / `systemError` / `active` だけを受理し、missing/unknown statusは過去turnが`completed`でも成功claimへ昇格させない。
- `active` は実行中、`systemError` はfailure、`idle/notLoaded`単独は成功と推定しない。
- latest turn `completed` はprovider terminal success claim / `ARTIFACT_READY`までであり、Controller `PASS` ではない。
- thread ID不一致、malformed response、SDK version/API drift、timeoutは成功へ推定せずfail closed。
- official low-level `CodexClient` の既定approval handlerがapproval requestをacceptし得るため、その既定handlerを使用しない。read-only observerではserver-initiated requestを明示的に例外化し、approval/mutationへ進ませない。
- このsliceは `start` / `initialize` / `thread_read` / `close` のapp-server lifecycle/read以外のprovider操作を要求しない。thread/turn start、resume、send、steer、interrupt、approval、dispatch、GitHub Ready/merge、deploy/release等は追加しない。
- deterministic CIはfake SDK clientのみを使用し、live Codex account/binaryを要求しない。

### Review remediation

- initial exact-head Codex reviewで、live dependency未宣言（P1）とunknown thread statusからhistorical completed turnをsuccessへ昇格できる問題（P2）が指摘された。
- P1は `requirements-codex.txt` の追加とSDK version固定で修正。
- P2はknown thread status validationをterminal-turn判定より先に行うよう修正し、regression testを追加。
- self-reviewで、公式low-level clientのconstructor契約・request timeout欠如・既定auto-approval handlerを一次ソースから確認し、explicit config / timeout / reject handlerへ修正。

### Validation status

- この項目はDraft PR #103の未merge実装を記録しており、mainへの採用済み状態を意味しない。
- Ready / merge はADR #90に従いhuman-finalのまま。

---

## 2026-08-26 — MVP human-final loop（Draft PR #101）

関連: ADR Issue #90, Issue #100, Draft PR #101

### Added / changed

- watcher の fresh objective observation に `current_draft` / `current_merged` / `current_state_enum` を明示的に含める。
- human-attention queue に表示専用の `human_action` を追加。
- verified `REVIEW_READY` の Draft PR は `MARK_READY_FOR_REVIEW`、non-Draft open PR は `MERGE` を一つの明示的な人間操作として提示する。
- human action 後は acknowledgement token を作らず、次の通常の read-only watch が GitHub authoritative state を再読して次の action または `DONE` へ進む。
- closed-without-merge と merged terminal state を区別して表示する。
- GitHub PR details で `draft` / `merged` が欠落した場合、`False` に補完せず unknown のまま fail closed する。

### Safety / trust boundary

- `human_action` は authorization ではなく表示情報のみ。
- `human_action` の提示には nonempty current head、exact-head Actions `PASS`、`scope_status=SATISFIED`、`graphql_error=false`、coherent current PR state を要求する。
- inspection/API failure 時は last-known-good の draft/merged/state を current action basis として再利用しない。
- contradictory / missing evidence は `NEEDS_ATTENTION` に fail closed し、Ready / merge を提示しない。
- Controller code に Ready / merge / auto-merge その他の LEVEL 3 mutation capability を追加しない。
- Phase 4B の write-capable reconciler は LEVEL 3 human-final flow には再利用しない。

### Validation status

- exact head `ae1b2427af4924910dd6300237b3b2ab03bca210` で deterministic Actions CI success。
- 同 head に対する Codex independent review は major issue なし。
- この項目は Draft PR #101 の未merge実装を記録しており、main への採用済み状態を意味しない。

---

## 2026-08-30 — Live official Jules API adapter slice (v1alpha)

関連: ADR Issue #12, ADR Issue #90, Issue #116

### Added / changed

- 既存の `ProviderDispatchClient` および `ProviderReadClient` 抽象の背後に、公式 Jules REST API (`v1alpha`) に直接接続する `JulesApiClient` (`agent_controller/jules_live.py`) を追加。`urllib.request` のみを使用し外部依存を持たない。
- `JulesDispatchClient` を追加し、明確に指定された `controller_task_id` / `operation_id` / `repo` / `expected_start_ref` / `expected_start_sha` から `POST /v1alpha/sessions` (`requirePlanApproval=True`, `automationMode="AUTOMATION_MODE_UNSPECIFIED"`) を呼び出して `ProviderOperationRef` を生成。
- `JulesReadClient` を追加し、`GET /v1alpha/sessions/{id}` から生の Jules セッションデータを取り出し。
- `map_jules_observation` を更新し、公式 `v1alpha` API の `state` フィールド (`QUEUED`, `IN_PROGRESS`, `AWAITING_USER_FEEDBACK`, `PAUSED`) および `updateTime` を認識・マッピング可能に拡張。不明なステータスは `UNCERTAIN` へ fail closed。
- CLI コマンド `dispatch-jules` および `observe-jules` を追加。

### Safety / credential boundary

- 認証キーは `JULES_API_KEY` 環境変数または明示設定からのみ取得し、`X-Goog-Api-Key` HTTP ヘッダーとして送信。
- ネットワーク要求前にキーの存在をチェックし、キーが欠落している場合は即座に fail closed。
- エラーハンドリングにおいて例外メッセージ中の API キー文字列をサニタイズ (`[REDACTED]`) し、キーの漏洩・ログ・出力・永続化を防止。
- テストおよび CI はインジェクトされた偽のトランスポートを用い、外部の Jules ライブ API に一切依存しない。
- 検出された `COMPLETED` ステータスは provider の成果物準備完了の主張 (`ARTIFACT_READY` / `TerminalClaim.SUCCESS`) であり、Controller の最終評価 (Controller PASS) や GitHub への自動公開証明ではない。
- Ready / merge は ADR #90 に従い human-final のまま。

---

## [Unreleased] — Phase 4C-PN1 provider-neutral proof

### 2026-08-24 — provider-neutral contract proof を実装中

関連: Issue #14, ADR Issue #12, reset Issue #13

#### Added

- `agent_controller/provider_contract.py` を追加し、provider-neutral な最小モデルを導入。
  - `TaskBinding`
  - `ProviderOperationRef`
  - `AgentObservation`
  - `ArtifactEvidence`
  - `ObjectiveScope`
  - provider-neutral `ControllerState` の必要最小 subset
  - `AwaitingInput`
  - `TerminalClaim`
  - `VerificationResult`
  - `VerificationSource`
- `AgentAdapter` Protocol を導入。
- provider-neutral contract tests を追加。
- Jules と Codex の二つの異なる provider fixture が、同じ Controller contract / flow を通る dual-provider proof を追加。
- `agent_controller/provider_mappers.py` を追加。
  - `map_jules_observation()`
  - `map_codex_observation()`
- Jules / Codex の provider-native raw state を pure mapper で `AgentObservation` に正規化するテストを追加。
- fixture adapter の `observe()` を pure mapper 経由へ変更し、adapter が `AgentObservation` を直接組み立てない責務分離を固定。
- `agent_controller/provider_clients.py` を追加し、観測専用の `ProviderReadClient` Protocol を導入。
  - mandatory surface は `get_operation_raw()` の1メソッドのみ。
  - official SDK / CLI / Action result / fixture のいずれでも薄くラップできる read-only 境界とした。
- `agent_controller/provider_adapters.py` を追加。
  - `JulesObservationAdapter`
  - `CodexObservationAdapter`
- production側の観測専用adapterを、`ProviderReadClient -> raw payload -> pure mapper -> AgentObservation` の構造で追加。
- provider target mismatch を client read 前に拒否する deterministic test を追加。
- `agent_controller/provider_artifacts.py` を追加。
  - `ProviderArtifactReadClient`
  - `map_jules_artifact()`
  - `map_codex_artifact()`
  - `JulesArtifactAdapter`
  - `CodexArtifactAdapter`
- provider-reported artifact の取得を observation client とは別 capability に分離。
- `ProviderArtifactReadClient -> raw artifact -> pure artifact mapper -> ArtifactEvidence` の read-only 経路を追加。
- Codex の review-only artifact を code publication なしで表現できる deterministic test を追加。
- `agent_controller/artifact_verifier.py` を追加。
  - read-only `GitHubArtifactReadClient` Protocol
  - `verify_github_artifact()`
- provider-reported artifact を provider 名に依存せず、GitHub objective facts で独立検証する共通経路を追加。
- GitHub ref resolution、provider-reported SHA 一致、start SHA からの freshness、ancestry、changed-file scope を順に検証。
- Phase 3A の `evaluate_scope()` を再利用し、path-scope policy を二重実装しない構造とした。

#### Changed

- 当初 `AgentAdapter` に含まれていた `capabilities` property を mandatory surface から除外。
- core が必須とする adapter surface を次の3操作だけに縮小。
  - `dispatch()`
  - `observe()`
  - `collect_artifacts()`
- optional capability は provider asymmetry を保ったまま、core mandatory protocol とは別に扱う方針を明確化。
- read-only observation adapter は、不要な `dispatch()` のダミー実装を持たせず、現段階では意図的に full `AgentAdapter` を満たさない設計とした。
- artifact read capability も operation observation と分離し、provider が一方だけを提供する場合に不要な capability を強制しない設計とした。
- artifact verification は provider adapter 内では行わず、共通の GitHub verifier へ分離した。

#### Safety / trust boundary

- Jules / Codex / Manus 固有の lifecycle state を Controller core state に入れない。
- provider raw state は opaque evidence として保持し、core が provider 名で分岐しない構造を目標とする。
- unknown / malformed provider state は推測で成功状態へ寄せず `UNCERTAIN` に fail closed。
- provider が成功・完了・commit 作成を主張しても、それだけでは Controller PASS にしない。
- `provider_reported_sha` と `verified_sha` を分離し、provider 自己申告 artifact を独立検証済みとして扱わない。
- provider-specific network transport はこの proof slice では実装しない。
- `ProviderReadClient` は approve / send / retry / cancel / dispatch / create / update / delete / merge / deploy 等の mutation surface を持たない。
- observation adapter も dispatch / mutation authority を持たず、read-only slice に不要な権限を導入しない。
- `ProviderArtifactReadClient` は artifact read のみを持ち、mutation surface を持たない。
- provider が ref / SHA / content hash を報告しても、artifact mapper / adapter は `independently_verified=True` を設定しない。
- unparseable artifact は `artifact_kind="unknown"` / `freshness_basis="provider_report_unparseable"` として保持し、成功や検証済み状態へ推定しない。
- artifact adapter の provider target mismatch は client read 前に拒否する。
- GitHub verifier だけが `independently_verified=True` / `verification_result=PASS` へ昇格できる。
- ref / SHA / ancestry / scope の明確な不一致は `FAIL`、必要binding不足は `BLOCKED`、GitHub read/compare不確実性は `UNCERTAIN` として区別する。
- unchanged start SHA は fresh artifact と認めない。
- Jules と Codex で verifier rules を分岐しない。

#### Commits reconstructed for this slice

- `6eeded2aa3ea93be7b0dfd7306829377b2e23f13` — provider-neutral contract models を追加。
- `a3e59e23244f91d033d1550f8a04c1a7233ff9ea` — `AgentAdapter` mandatory surface を3操作へ修正。
- `816ea118835f20694f730574375c1b5ab98c3620` — provider-neutral contract tests を追加。
- `1ac0d5c35d8369bc467951df512fb4617ad0c93f` — Jules / Codex dual-provider contract flow proof を追加。
- `f2133e060e04a9a5b580e1662a8d9f4d0d408623` — pure Jules / Codex observation mapper を追加。
- `9c6592502b85102d5ffbde4459ffa2ced9dc4cbd` — provider mapper tests を追加。
- `f203a9e4611d78c3295c9449c4a5934ac04d2284` — fixture adapter を pure mapper 経由へ変更。
- `20d4c77db832a7095863cc27ad0e3c747a69d420` — reconstructed `CHANGELOG.md` を導入。
- `b55196f7ea7efbc874c8fa5a408073133570dd77` — read-only `ProviderReadClient` contract を追加。
- `48bb4f823bdecae3d4807434ce686c7fcbfc2fdc` — fixture flow を injected read client 経由へ変更。
- `506e5548545e3a3339e5119e7deb5ed04f4c1447` — read-only client boundary tests を追加。
- `bed1d852c7f9d155bf3b33b032ba5ad419a4ce13` — production read-only Jules / Codex observation adapters を追加。
- `6460387d70d9eb95f51b01e51a1769cf15c9d517` — observation adapter responsibility / authority boundary tests を追加。
- `9b3ba83ee51f180f819650d4d16c8bcf3611e5c8` — read-only observation boundary を CHANGELOG に記録。
- `a1d244d017407787fbaf4023c15b5744bf3f5f9b` — provider artifact read / mapping / adapter boundaries を追加。
- `200e29f51dd72c041f99f17a0e7f136cd3466491` — artifact trust / capability boundary tests を追加。
- `2e50e81d662268b17efffccf1b5f3e1e963bfecf` — provider artifact boundary を CHANGELOG に記録。
- `5cc1588158e6b7cf52f12f8f2f8cf72b6df760a2` — provider-neutral GitHub artifact verifier を追加。
- `6c7a35f1ca30fea6f47d4b3b0b47e22e37afca3b` — artifact verifier tests を追加。

---

## [Unreleased]

関連: Issue #168, PR #169

### Added

- provider-capacity observation/recommendation boundaryを明示。
- bounded freshness semantics (有効期限) の導入によるstale observation失効の確実化。
- paid-usage boundary、review-provider preservation の要件を明示。
- recommendation-only / no-side-effect authority を維持する設計。

---

## 2026-08-23 — Phase 4C architecture reset / provider-neutral decision

関連: Issue #10, Draft PR #11, ADR Issue #12, Issue #13, Issue #14

### Background

Phase 4B 後、残っていた人手の relay は Jules session の作成・状態確認・plan approval・message transport・GitHub artifact handoff だった。

そのため Issue #10 では、Jules REST transport と GitHub artifact handoff を Controller 内に実装する方向を定義した。

Draft PR #11 `Phase 4C: Automate Jules REST transport and GitHub artifact handoff` が作成され、Jules REST transport / lifecycle / persistence / GitHub verification をまとめて実装する prototype が進んだ。

### Architecture correction

その後、ADR Issue #12 で standing architecture を変更・明文化。

- Agent Controller は **provider-neutral control plane** とする。
- Jules 固有 orchestrator にしない。
- Jules / Codex / owner-machine execution / future providers は adapter 後段の heterogeneous worker とする。
- provider transport は reuse-first とし、次の優先順位を採用。
  1. official stable API / CLI / Action
  2. official or vendor-maintained SDK / extension
  3. established OSS
  4. thin wrapper / adapter
  5. custom implementation は Controller 固有の gap に限定
- 少なくとも二つの materially different provider で検証するまで、provider-neutral contract を固定しない。
- agent は untrusted worker とし、agent claim は advisory とする。

Issue #13 で Phase 4C を reset。

- PR #11 を requirements-discovery / Jules-adapter prototype と再分類。
- PR #11 の内容を KEEP / REPLACE / DELETE の観点で監査。
- bespoke Jules REST transport を Controller core として継続しない方針を採用。
- Jules は公式 `@google/jules-sdk` 等を優先。
- Codex は公式 SDK / CLI / GitHub integration / Action を優先。
- Controller 固有 custom code は approval / evidence / stale detection / GitHub authority / freshness / audit 等へ限定。

Issue #14 で Phase 4C-PN1 を定義し、provider-neutral contract を Jules と Codex の双方で証明する方向へ移行。

### PR #11 status

- Draft
- open
- unmerged
- historical prototype / requirements-discovery evidence として保持
- PN1 中には merge / remediation push を行わない方針

---

## 2026-08-23 — Phase 4B: deterministic reconciliation

関連: Issue #8, PR #9

Merged main: `1cda192b8013f40faa3deabfe44955a1394630e5`

### Added

- Phase 3B observation と Phase 4A executor を接続する one-cycle reconciliation primitive を追加。
- `reconcile-pr` CLI を追加。
- objective transition を action planning / execution へ接続。
- first observation は baseline establishment のみとし、初回観測で mutation しない semantics を導入。
- duplicate action suppression 用の action receipt persistence を導入。
- verified postcondition 後にのみ success receipt を記録する設計を採用。

### Safety / trust boundary

- Phase 4B 自体は新しい GitHub write capability を追加しない。
- mutation capability は Phase 4A の `ENSURE_DRAFT` のみ。
- fail-closed observation で last-known-good state を上書きしない。
- stale target/head/state は execution 前に再確認し block。
- duplicate / consumed transition からの再mutationを抑制。
- agent-authored token を receipt authority として使わない。

### Notable remediation

- reconciliation target に lock identity を binding し、concurrency leak を修正。

---

## 2026-08-22 — Phase 4A: deterministic low-risk executor

関連: Issue #6, PR #7

Merged main: `f979ea2c5705553d78370d711bc8c30f960234d0`

### Added

- 初の write-capable Controller slice を追加。
- mutation は `ENSURE_DRAFT` のみに限定。
- explicit local policy による allowlist gate を追加。
- dry-run / apply separation を導入。
- plan と execution を target/head に binding。
- mutation 直前の GitHub re-read と stale detection を導入。
- mutation 後の objective postcondition verification を追加。
- repeated execution の idempotency をテスト。

### Safety / trust boundary

- policy absent / malformed / action not allowlisted は BLOCKED。
- closed / merged / stale / contradictory evidence / API failure は fail closed。
- merge、Ready-for-review、comment、label、review request、branch/ref/file write、workflow dispatch、Jules/Codex trigger、release/deploy 等の capability を executor に持たせない。
- `--apply` は action set を広げず、単一cycleの既承認 low-risk action だけを許可。

---

## 2026-08-22 — Phase 3B: read-only PR watcher

関連: Issue #4, PR #5

Merged main: `574877c6758864a6e92b275d46d41c2570fab042`

### Added

- Phase 3A inspector を繰り返し利用する read-only PR watcher を追加。
- `watch-pr` / deterministic `--once` behavior を追加。
- previous / current observation の比較と state-transition detection を追加。
- head SHA、classification、Draft/open/merged、evidence availability の変化を transition evidence として扱う。
- local state persistence を導入。

### Safety / trust boundary

- identical observation は duplicate transition を発生させない。
- head SHA の変更だけを progress / success と見なさず、必ず再inspection。
- inspector/API failure は explicit fail-closed observation として扱う。
- inspection failure 時に last-known-good state を synthetic uncertainty で上書きしないよう remediation。
- corrupt prior local state を明示的に検出。
- GitHub write / agent trigger は導入しない。

---

## 2026-08-20 — Phase 3A: read-only GitHub PR completion detector

関連: Issue #2, PR #3

Merged main: `dea58b77480e925237a5bfd3b1015741cde122bc`

### Added

- `inspect-pr` CLI を追加。
- GitHub の objective evidence から PR orchestration state を判定する read-only inspector を実装。
- PR state / Draft / base / head SHA / changed files / comments / reviews / review threads / reactions / CI checks を観測。
- `IMPLEMENTATION_READY` / `REVIEW_READY` / `NEEDS_REVIEW` 等の分類を導入。
- current-head SHA に review evidence を binding。
- changed-file scope policy (`allowed_paths`, `denied_paths`, docs-only handling) を導入。
- GraphQL review thread pagination、check-run error handling、diff summary 等を追加。

### Safety / trust boundary

- agent self-report は advisory only。
- commit count / head change だけでは meaningful implementation と判定しない。
- stale review を current head に適用しない。
- reaction-only clean review は SHA binding の信頼性が不足する場合 fail closed。
- scope policy がない / evidence が不明な場合は成功へ推定しない。
- Phase 3A は GitHub write capability を持たない。

### Validation rationale

初期 validation target として `oimus1976/calendar-csv2ics-converter` PR #5 を利用する設計が Issue #2 に記録されている。

---

## 2026-08-20 — Trust-boundary specification / pre-Controller experiment reconstruction

関連: Issue #1

Agent Controller 本体の実装以前に、`oimus1976/calendar-csv2ics-converter` を使い、Jules を implementation worker、Codex を independent reviewer とする実験を実施。

Issue #1 に保存された主要観測:

- Jules は repository inspection、実装、test追加、commit、push、PR作成まで実行できた。
- 指示では Draft PR が要求されていたが、Jules が non-Draft PR を作成し delivery boundary violation が発生。
- Codex が independent review で test discovery / execution に関する P2 concern を検出。
- Jules が remediation を行い clean clone validation を報告。
- follow-up Jules commit の一つは parent SHA は変わったが effective diff が空であり、commit 数だけでは progress を証明できないことを確認。
- Codex を latest head に対して再実行し、最新SHAに対する clean result を得る必要があった。
- implementation / review / fix / re-review の loop を GitHub artifacts から観測可能であることを確認。

### Core rules derived

- GitHub artifacts / refs / SHA / diffs / checks / review state を primary evidence とする。
- agent self-classification / UI state / completion message を authority としない。
- LEVEL 3 は capability-gated とし、merge / production / irreversible effect 等には explicit human approval を要求する。
- indirect / cumulative effects も risk classification に含める。
- implementation readiness は artifact-based predicate とする。
- independent review は reviewed SHA に binding する。
- human-gate readiness と agent completion を分離する。

### Historical gap

Issue #1 は次の experiment として Phase 1B Jules REST API observation を示唆しているが、現時点の `agent-controller` repository で検索できた durable Issue / PR からは、Phase 1B および Phase 2 の独立した実装履歴を十分に再構成できていない。

この期間は推測で補完せず、追加の一次情報が見つかった場合に追記する。

---

## 2026-08-20 — Repository initialized

Initial commit: `1b5a4b5423a22e1e31ecc4e76a8ede19b28a8674`

Agent Controller repository の初期commit。

---

## Historical references

主要な durable records:

- Issue #1 — GitHub-grounded completion detection / trust boundaries
- Issue #2 / PR #3 — Phase 3A PR Inspector
- Issue #4 / PR #5 — Phase 3B PR Watcher
- Issue #6 / PR #7 — Phase 4A deterministic `ENSURE_DRAFT` executor
- Issue #8 / PR #9 — Phase 4B reconciliation
- Issue #10 / Draft PR #11 — original Jules-centric Phase 4C prototype
- Issue #12 — provider-neutral / reuse-first architecture ADR
- Issue #13 — Phase 4C architecture reset and PR #11 KEEP / REPLACE / DELETE audit
- Issue #14 — Phase 4C-PN1 provider-neutral proof slice

今後は、意味のある Phase / architecture / authority boundary の変更を merge する際に、この CHANGELOG も同じ変更系列で更新する。

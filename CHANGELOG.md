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

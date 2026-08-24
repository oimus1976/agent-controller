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

#### Changed

- 当初 `AgentAdapter` に含まれていた `capabilities` property を mandatory surface から除外。
- core が必須とする adapter surface を次の3操作だけに縮小。
  - `dispatch()`
  - `observe()`
  - `collect_artifacts()`
- optional capability は provider asymmetry を保ったまま、core mandatory protocol とは別に扱う方針を明確化。

#### Safety / trust boundary

- Jules / Codex / Manus 固有の lifecycle state を Controller core state に入れない。
- provider raw state は opaque evidence として保持し、core が provider 名で分岐しない構造を目標とする。
- unknown / malformed provider state は推測で成功状態へ寄せず `UNCERTAIN` に fail closed。
- provider が成功・完了・commit 作成を主張しても、それだけでは Controller PASS にしない。
- `provider_reported_sha` と `verified_sha` を分離し、provider 自己申告 artifact を独立検証済みとして扱わない。
- provider-specific network transport はこの proof slice では実装しない。

#### Commits reconstructed for this slice

- `6eeded2aa3ea93be7b0dfd7306829377b2e23f13` — provider-neutral contract models を追加。
- `a3e59e23244f91d033d1550f8a04c1a7233ff9ea` — `AgentAdapter` mandatory surface を3操作へ修正。
- `816ea118835f20694f730574375c1b5ab98c3620` — provider-neutral contract tests を追加。
- `1ac0d5c35d8369bc467951df512fb4617ad0c93f` — Jules / Codex dual-provider contract flow proof を追加。
- `f2133e060e04a9a5b580e1662a8d9f4d0d408623` — pure Jules / Codex observation mapper を追加。
- `9c6592502b85102d5ffbde4459ffa2ced9dc4cbd` — provider mapper tests を追加。
- `f203a9e4611d78c3295c9449c4a5934ac04d2284` — fixture adapter を pure mapper 経由へ変更。

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

### Phase 1A-1 observations preserved in Issue #1

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

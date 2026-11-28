# Draft PRを1操作進める

Issue [#215](https://github.com/oimus1976/agent-controller/issues/215#issuecomment-6925020137) のオンデマンド入口。毎回GitHubの最新HEAD、CI、canonicalレビュー証拠を読み、JSONの `state`・`reason`・`next_action` を返す。`--apply` は既存のレビュー要求または修正要求を最大1回投稿する。待機、再実装、Ready/mergeを自動で繰り返す機構はない。

リポジトリrootから同じコマンドを使う。最初は `--apply` を外すと観測と計画だけになる。

```text
python -m agent_controller.cli advance-pr --repo OWNER/REPO --pr 123 --policy policy.local.json --allowed-paths "agent_controller/*" "tests/*" "docs/*" --apply
```

GitHub認証と操作許可は既存 `request-codex-review` / `request-codex-remediation` と同じ。`GITHUB_TOKEN` はファイルや公開証拠へ書かない。変更パス制限は対象Issueに合わせる。

### 容量観測（手動policy / live Codex opt-in）

既定は従来どおり手動policy方式を維持する。ローカル `codex app-server` から実測容量を直接読む場合は `--codex-live-capacity` を明示指定する（必要に応じ `--codex-command` / `--codex-timeout` を併用）。`--codex-live-capacity` 無しで `--codex-command` / `--codex-timeout` を指定するとエラーで停止する（既存の `--codex-bin` は手動モードでも従来どおり許容される）。

手動policy例（時刻は実際の観測時刻に置き換える）：

```json
{
  "allowed_actions": ["REQUEST_CODEX_REVIEW", "REQUEST_CODEX_REMEDIATION"],
  "trusted_review_request_authors": ["OWNER"],
  "advance_pr": {
    "max_remediation_rounds": 3,
    "additional_paid_usage_required": false,
    "capacity": {
      "availability": "AVAILABLE",
      "source": "OPERATOR_OBSERVED",
      "observed_at": "2026-11-17T00:00:00Z"
    }
  }
}
```

`--codex-live-capacity` を使う場合のローカルpolicy例（`capacity` の手動転記は不要、実行時にpolicyファイルは書き換えない）：

```text
python -m agent_controller.cli advance-pr --repo OWNER/REPO --pr 123 --policy policy.local.json --allowed-paths "agent_controller/*" "tests/*" "docs/*" --codex-live-capacity --apply
```

```json
{
  "allowed_actions": ["REQUEST_CODEX_REVIEW", "REQUEST_CODEX_REMEDIATION"],
  "trusted_review_request_authors": ["OWNER"],
  "advance_pr": {
    "max_remediation_rounds": 3,
    "additional_paid_usage_required": false
  }
}
```

- **遅延収集:** 既存plannerが `EXECUTABLE` と判定し、`additional_paid_usage_required: false` が確認できたレビュー／修正要求に限り `capacity_collect.read_codex_rate_limits_result` を呼ぶ（ダッシュボードJSONは経由しない）。`WAIT_CI`・`WAIT_CURRENT_HEAD_REVIEW`・`HUMAN_GATE_READY` や拒否／不要状態では収集しない。
- **対象poolとfail-closed:** 応答の `ordinaryUsageAllowed` が `false`（`ORDINARY_USAGE_NOT_ALLOWED`）または `null` の場合は停止する。曖昧でない `codex` バケットの `codex-five-hour` と `codex-weekly` の両方を `codex_capacity` と `provider_capacity` (`recommend_provider`) で評価し、枯渇・枠欠落・曖昧（複数バケットや未分類窓など）・取得失敗・`UNKNOWN`・期限切れ／`resetsAt` 欠落または到達では `WAIT_CAPACITY` で停止し、手動 `capacity` への暗黙fallbackや有料fallbackは行わない（手動モードの任意 `reset_at` 互換性は維持）。
- **独立観測と投稿直前鮮度:** dry-run と `--apply` は独立に観測する。観測有効期間は300秒で、`--apply` では要求投稿の最終ゲート直前まで300秒以内かつreset未到達を維持し、executorが読んだ最新policyと `additional_paid_usage_required: false` の整合性も最終ゲートで照合する。
- **AC-7（実利用効果）:** 実利用での手動転記回数削減の測定はコード統合とは別に追跡され、本手順書更新時点では未測定。

容量観測の有効期間は5分。`AVAILABLE` / `DEGRADED` と既知の観測元が必要で、`UNKNOWN`・期限切れ・reset時刻到達では再観測を求める。既存 `recommend_provider` を再利用し、追加課金が必要／不明なら停止する。手動モードでCodexのquota自動取得や有料fallbackはない。

| state | 次の操作 |
|---|---|
| `WAIT_CI` | 現HEADのCI完了後に再実行 |
| `REQUEST_REVIEW` | dry-runなら `--apply` でレビュー要求 |
| `WAIT_CURRENT_HEAD_REVIEW` | 要求は実行結果ではない。現HEADレビュー後に再実行 |
| `STOP_REMEDIATION_SCOPE` | 現HEADの全指摘について下記スコープ確認 |
| `REMEDIATE_SCOPED` | dry-runなら `--apply` で修正要求 |
| `WAIT_REMEDIATION` | タスク完了後に再実行 |
| `STOP_TASK_OBSERVATION_REQUIRED` | `View Task` を開き、完了と適用可否を確認 |
| `STOP_FOR_HUMAN_APPLY` | `View Task → Update branch`、その後再実行 |
| `STOP_HEAD_CHANGED` | 新HEADで再実行。以前のCI・レビューは使わない |
| `WAIT_CAPACITY` | `--codex-live-capacity` ならローカルCodex容量・追加費用policyを確認して再実行（手動・有料fallbackなし）；手動モードは容量・追加費用を再観測してpolicy更新 |
| `STOP_BUDGET` | 人間が修正計画を見直す |
| `HUMAN_GATE_READY` | 表示されたPR・HEAD・CI・レビューを確認し、人間がReadyを判断 |

その他の `STOP_*` は `reason` と `next_action` を確認する。失敗した要求を盲目的に再投稿しない。

## 修正範囲の確認

既存plannerは変更パスを検証するが、指摘の意味的スコープを判定しない。入口では現HEADの未解決Codex inline指摘のうち `P0` / `P1` / `BLOCKER` / `MAJOR` だけを候補にし、未分類・P2/P3は `STOP_FINDINGS` で止める。修正要求は固定文面 `@codex address that feedback` のため、指摘の一部だけを選べない。人間は現HEADの全指摘が凍結したIssue/AC内の狭い変更で解決できることを確認してから、次の2項目をローカルpolicyに設定する。

```json
{
  "advance_pr": {
    "bounded_remediation_head": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "bounded_remediation_findings": "<出力のfinding_set_sha256をコピー>"
  }
}
```

これは先のpolicyへ追記する部分だけを示す。`bounded_remediation_findings` は64桁のSHA256で、自分で計算せず出力値を使う。MINORのみ、分類不明、要件変更、新依存・外部サービス・課金経路・権限変更が必要なら設定せず停止する。

HEADが同じでも指摘は編集される。P1指摘を確認した後、P3へ変わった同一HEADに修正要求できる経路が独立レビューで再現されたため、HEADだけでなく指摘集合も固定する。実行時の最終確認でも照合し、指摘が変われば再確認へ戻す。既存policyの小さな確認項目であり、別の承認サービスや台帳は追加しない。

この確認はHEAD変更で無効になる。`max_remediation_rounds` はこのPRのtrusted修正要求markerにある異なるsource-head数の上限で、起動ごとにリセットしない。履歴を残すこと。0なら新規修正要求を許可しない。既に修正要求したHEADと同じ本文（空白等を正規化）の指摘が現HEADに再発すると `INEFFECTIVE_REMEDIATION` で停止する。意味の同じ言い換えまで検出する機能はない。新しい指摘が出るたびに無制限に上限を増やさない。

## Codexタスクと適用待ち

Cloud Codexタスクの完了／Update branch可否を取得するAPIは既存コードにない。GitHub側のタスク自動pollingも行わない。`observe-codex` はローカルrollout観測でありCloudタスクの代用にならない。同一source-headへの要求済みmarkerがあれば再要求を止める。

UIで直接確認できた状態は、任意のローカルJSONを `--codex-task-observation task.local.json` に渡せる：

```json
{
  "repo": "OWNER/REPO",
  "pr": 123,
  "source_head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "status": "complete_pending_apply"
}
```

`status` は `running` / `complete_pending_apply` / `failed`。repo・PR・source-headが一致したときだけ使い、人間の観測という出所を保つ。古いファイルは使い回さず状態を再確認する。これは停止先を選ぶ補助であり、GitHub公開・レビュー成功・Ready権限の証拠にはならない。完了・適用待ちは未実装と違うため、Update branchが利用できる間は同じ修正を再実装しない。適用後はGitHubの新HEADを読み、CIと独立レビューを取り直す。

常駐監視、別providerへの自動切替、runnerやowner-machine操作は対象外。Ready後のmergeも人間が判断する。

## Draft作成・push直後の有界follow（#340）

実装エージェントはDraft作成またはpush後に、検証済みのPR番号と40桁のHEADを指定して起動できる。既定は読み取り専用。対象・HEAD・許可する操作が明示された実行計画でのみ `--apply` を付け、既存policy、指摘集合の確認、追加課金禁止を満たす。新HEADでは、そのHEADを指定して別のfollowを起動する。

```text
python -m agent_controller.cli advance-pr --follow --repo OWNER/REPO --pr 123 --expected-head FULL_SHA --policy policy.local.json --allowed-paths "agent_controller/*" "tests/*" "docs/*" --codex-live-capacity --interval 60 --max-polls 60 --max-elapsed-seconds 3600 --result-file follow-123.json
```

- `WAIT_CI` と `WAIT_CURRENT_HEAD_REVIEW` の間だけ再観測する。要求が実行可能になってから容量を取得する。dry-runは実行可能な操作を表示した時点で終了する。現HEADへ同じレビュー要求を繰り返さない。
- `HUMAN_GATE_READY` は人間のReady判断で停止する。修正要求を投稿したとき、または既存要求を見つけたときは、[#200](https://github.com/oimus1976/agent-controller/issues/200) に従って停止し、必要に応じて人間が `View Task → Update branch` を確認する。HEADが動いた場合は両SHAを記録し、旧HEADで承認された処理を続けない。
- 観測と待機の合計は `--max-elapsed-seconds`、観測回数は `--max-polls` で制限する。各観測の外部呼び出しを含む上限は残り時間と120秒の短い方。処理中のタイムアウトでは、投稿が届いた可能性を残して停止するため、再実行前にGitHub上の要求を確認する。
- 同じPRのfollow、`advance-pr --apply`、`reconcile-pr` は同じローカルロックを使う。競合したfollowは `STOP_CONFLICT` を同じディレクトリの競合専用JSONに保存する。保存先は標準出力の `result_file`、実行中の処理の保存先は `shared_result_file` で確認できる。単発dry-runはロックを取得しない。残ったロックを自動解除しない。
- 終了結果は指定したローカルJSONへ原子的に書き、標準出力にも返す。省略時は同じOS一時ディレクトリにあるPRロックと同じ名前の `.result.json`。複数PRに同一の結果ファイルを指定しない。通知は既定で無効。`--notify-mode bell|windows-toast|command` は結果保存後に一度だけ実行し、別枠で10秒に制限する。`command` にはローカル実行ファイルまたは `.py` を指定し、結果ファイルの絶対パスが単一引数で渡る。通知失敗でも結果から停止理由を読める。Windowsトーストは対話デスクトップに依存する。

### 起動したエージェントの終了後も続ける場合

作業用worktreeと既存のGitHub認証が使えるホスト上で、一回限りのPythonプロセスとして起動する。Windows PowerShellでは作業用worktreeで以下を実行する。例の相対パスはworktree内を指す。標準出力と標準エラーは起動ごとに別ファイルを指定する。

```powershell
$followArgs = @('-m', 'agent_controller.cli', 'advance-pr', '--follow',
    '--repo', 'OWNER/REPO', '--pr', '123', '--expected-head', 'FULL_SHA',
    '--policy', 'policy.local.json', '--allowed-paths', 'agent_controller/*', 'tests/*', 'docs/*',
    '--max-polls', '60', '--max-elapsed-seconds', '3600', '--result-file', 'follow-123.json')
Start-Process -FilePath (Get-Command python).Source -WorkingDirectory (Get-Location).Path -ArgumentList $followArgs -WindowStyle Hidden -RedirectStandardOutput 'follow-123.stdout.json' -RedirectStandardError 'follow-123.stderr.log'
```

Unix系では同じ引数のPythonコマンドを `nohup` で起動し、標準入力を `/dev/null`、標準出力・標準エラーをローカルファイルへリダイレクトしてバックグラウンドに置く。エージェントの終了時に子プロセス一式を破棄する環境では、その環境外の既存ホストの起動経路を使う。起動はプロセスと起動ログで確認し、停止理由を読むときは結果JSONの `started_at` と `initial_head_sha` を照合する。

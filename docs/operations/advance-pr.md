# Draft PRを1操作進める

Issue [#215](https://github.com/oimus1976/agent-controller/issues/215#issuecomment-6925020137) のオンデマンド入口。毎回GitHubの最新HEAD、CI、canonicalレビュー証拠を読み、JSONの `state`・`reason`・`next_action` を返す。`--apply` は既存のレビュー要求または修正要求を最大1回投稿する。待機、再実装、Ready/mergeを自動で繰り返す機構はない。

リポジトリrootから同じコマンドを使う。最初は `--apply` を外すと観測と計画だけになる。

```text
python -m agent_controller.cli advance-pr --repo OWNER/REPO --pr 123 --policy policy.local.json --allowed-paths "agent_controller/*" "tests/*" "docs/*" --apply
```

GitHub認証と操作許可は既存 `request-codex-review` / `request-codex-remediation` と同じ。`GITHUB_TOKEN` はファイルや公開証拠へ書かない。変更パス制限は対象Issueに合わせる。

ローカルpolicy例（時刻は実際の観測時刻に置き換える）：

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

容量観測の有効期間は5分。`AVAILABLE` / `DEGRADED` と既知の観測元が必要で、`UNKNOWN`・期限切れ・reset時刻到達では再観測を求める。既存 `recommend_provider` を再利用し、追加課金が必要／不明なら停止する。Codexのquota自動取得や有料fallbackはない。

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
| `WAIT_CAPACITY` | 容量・追加費用を再観測してpolicy更新 |
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

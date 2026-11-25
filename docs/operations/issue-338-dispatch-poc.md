# Issue #338 PoC: Issue受付からローカルClaude Codeの無人起動

Authority: [#338](https://github.com/oimus1976/agent-controller/issues/338)（[#336](https://github.com/oimus1976/agent-controller/issues/336) 第6段階の限定先行実証）。#335、#333その他のworkstreamは変更しない。この文書は準備状態と実行計画を記録する。実機変更、実CLI発火、認証変更は、本人が下記の各ゲートを個別に承認するまで行わない。

## 再利用した既存機能

| 用途 | 再利用元 |
| --- | --- |
| GitHub読み取り・コメント投稿 | 既存の `gh` CLIとkeyring認証（`repo` scope）。トークンは子プロセスへ渡さない |
| 容量判定 | `agent_controller.claude_code_capacity.parse_claude_code_statusline_capacity` と、#333と同じstatusline保存ファイル（読み取りのみ） |
| 定期起動 | `scripts/register-ai-usage-task.ps1` と同じScheduled Task構成（Limited、IgnoreNew、実行時間上限） |
| 一回分の消費 | 既存の `O_CREAT|O_EXCL` マーカー方式（`private_ci_*`、`execution_ledger` と同型） |

新規コードは `scripts/issue_dispatch_poc.py`（1回のpollだけを行う受付）と `tests/test_issue_dispatch_poc.py` だけである。

## 受付規則（実装済み）

- 固定の非公開repo、完全一致のラベル、許可した作成者の数値ID（`type: User`）、`armed_at` より後に作成されたIssueだけを候補にする。
- 本文は `task: summarize-fixture-v1` と完全一致する必要がある。本文はCLIにもシェルにも渡さない。プロンプトと入力ファイルはconfigで固定し、入力ファイルはSHA-256で照合する。
- コメント済み、PR、ロック済みのIssueを除外する。候補が2件以上なら起動しない。
- 認証が未ログイン、認証方式が許可リスト外、容量観測が欠落・2時間超・残量20%未満のいずれかに当たれば、消費せずに見送る。
- 起動直前に `state_dir/consumed.json` をO_EXCLで作成する。以後の実行は、成功・失敗・タイムアウトのいずれでも `already_consumed` で即終了する。
- CLIには `Read` ツールだけを許可する。`dontAsk` と `--permission-prompts none` で確認待ちを作らず、ユーザー設定・hook・MCPを読み込まない。子プロセスの環境から `GITHUB_TOKEN`、`GH_TOKEN`、`ANTHROPIC_API_KEY`、`ANTHROPIC_AUTH_TOKEN` を除く。
- 結果コメントは受付側が投稿する。コメントには終了コード、時刻、検知遅延、起動回数1を記載し、要約からトークン・メールアドレス・Windowsパスを伏せ字にする。失敗時は標準エラーを載せない。
- `--live` を付けない実行は、候補判定と事前確認だけを行い、CLI起動もコメント投稿もしない。

## 非liveテスト（AC1）

`python -m unittest tests.test_issue_dispatch_poc` で次を確認する：非対象（作成者・Bot・ラベル・古いIssue・不正本文・別タスク・コメント済み・PR・不正日時）、複数候補、期限外、未ログイン、API key認証、容量欠落・古い観測・低残量、入力ファイル改変、dry-run、1回起動と再発火なし、失敗・タイムアウト時の消費と失敗コメント、伏せ字、config検証。

## 実機preflight結果（2026-11-25、非破壊）

| 項目 | 結果 | 判定 |
| --- | --- | --- |
| Claude Code CLI | PATH上にない。desktop app同梱の `claude.exe` 2.1.330 だけが `<LOCALAPPDATA>\Claude-Data\<APP_ID>\claude-code\<VERSION>\<HASH>\` に存在する | パスはapp更新で変わる。configで固定し、消えれば `cli_missing` で見送る |
| CLI認証 | `claude auth status --json`: `loggedIn=false`、`authMethod=none`、`ANTHROPIC_API_KEY` 未設定 | **ブロッカー**。desktop appの認証は単体起動に引き継がれない |
| 容量観測 | statusline保存ファイルなし、`statusLine` 未設定 | **ブロッカー**。現状は容量不明のため実行しない |
| GitHub認証 | `gh` 2.98.0、keyring、scope `repo, workflow, read:org, gist` | 受付とコメントに十分 |
| 受付repo | 用途に合う既存の非公開repoはない | 作成が必要（G1） |
| スケジューラ | 同種の既存タスクなし | 新規登録が必要（G4） |
| Python / ディスク | Python 3.12.10、空き約70GB | 問題なし |

`claude -p` は実行していない。CLIの実呼び出しはAC3の承認後に1回だけ行う。

## 実行計画（各ゲートは本人の個別承認が必要）

### G1 受付repoの作成（visibility変更を伴う新規作成）

```powershell
gh repo create oimus1976/agent-dispatch-inbox --private --description "Issue #338 PoC intake (no code)"
```

```powershell
gh label create dispatch-poc --repo oimus1976/agent-dispatch-inbox --description "Issue #338 PoC dispatch" --color B60205
```

作成後に `gh api users/oimus1976 --jq .id` で作成者IDを読み、configの `allowed_author_id` に記入する。ChatがIssueを作成するときのGitHubアカウントがこのIDと一致することを先に確認する。Chat側の連携がBotやApp名義で作成する場合は、作成者規則を見直す必要がある。

### G2 単体CLIの認証（認証変更）

本人が対話端末で次を実行し、Claudeの定額契約アカウントでサインインする。

```powershell
& "<CLAUDE_EXE>" auth login
```

その後 `& "<CLAUDE_EXE>" auth status --json` の `authMethod` を読み、その値だけを `allowed_auth_methods` に記入する。API key方式の値は記入しない。これで追加課金の経路を受付側で拒否する。

### G3 容量観測（ユーザー設定変更）

`capacity_collect` の説明どおり、`statusLine` コマンドに標準入力を `%USERPROFILE%\.agent-controller\claude-statusline.json` へ保存するラッパーを設定する。#333も同じファイルを読む。設定後に対話セッションを1回使い、ファイルが2時間以内に更新されていることを確認する。この設定を見送る場合、受付は `capacity_unknown` で起動しない。

### G4 実証（live、1回限り）

1. 固定入力を `<STATE_ROOT>\fixture\fixture.md` に置き、`Get-FileHash -Algorithm SHA256` の値を `fixture_sha256` に記入する。
2. `<STATE_ROOT>\config.json` を作成する（例は下記）。`armed_at` は登録時刻、`expires_at` は2時間後とする。
3. dry-runで判定だけを確認する（Issue未作成なら `no_candidate`）。

```powershell
python "<WORKTREE>\scripts\issue_dispatch_poc.py" --config "<STATE_ROOT>\config.json"
```

4. タスクを登録する。1分間隔、`expires_at` で自動終了、多重起動は無視、実行時間上限は10分とする。

```powershell
$a = New-ScheduledTaskAction -Execute "<PYTHON>" -Argument '"<WORKTREE>\scripts\issue_dispatch_poc.py" --config "<STATE_ROOT>\config.json" --live --log-file "<STATE_ROOT>\poll.log"'
$t = New-ScheduledTaskTrigger -Once -At "<ARMED_AT_LOCAL>" -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Hours 2)
$t.EndBoundary = "<EXPIRES_AT_LOCAL_ISO>"
$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew -DeleteExpiredTaskAfter (New-TimeSpan -Days 1)
$p = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName "agent-controller issue-338 PoC" -Action $a -Trigger $t -Settings $s -Principal $p
```

5. Chatが受付repoに、ラベル `dispatch-poc`、本文 `task: summarize-fixture-v1` のIssueを1件作成する。以後、人間は操作しない。
6. 確認（AC4）：結果コメント、`<STATE_ROOT>\result.json`（CLI開始・終了時刻、終了コード、検知遅延、`launch_count`）、`poll.log` で `launched` が1行だけであること、その後の行がすべて `already_consumed` であること。
7. 停止：次を実行する。`consumed.json` は削除せず、再発火防止の証拠として残す。

```powershell
Unregister-ScheduledTask -TaskName "agent-controller issue-338 PoC" -Confirm:$false
```

config例（値はplaceholder）：

```json
{
  "repo": "oimus1976/agent-dispatch-inbox",
  "label": "dispatch-poc",
  "allowed_author_id": 0,
  "task_type": "summarize-fixture-v1",
  "armed_at": "<ARMED_AT_ISO_WITH_OFFSET>",
  "expires_at": "<EXPIRES_AT_ISO_WITH_OFFSET>",
  "state_dir": "<STATE_ROOT>\\state",
  "claude_exe": "<CLAUDE_EXE>",
  "fixture_dir": "<STATE_ROOT>\\fixture",
  "fixture_sha256": "<SHA256>",
  "statusline_path": "<USERPROFILE>\\.agent-controller\\claude-statusline.json",
  "allowed_auth_methods": ["<MEASURED_AUTH_METHOD>"],
  "claude_timeout_seconds": 300,
  "model": "sonnet"
}
```

## 残るリスク

- desktop appの自動更新で `claude.exe` のパスが変わると、受付は `cli_missing` で見送る。G4の直前にパスを再確認する。
- タスクはログオン中だけ動く（Interactive）。PCがスリープ中の場合、検知遅延が増えるか、期限切れで終了する。
- 起動前の消費を優先するため、CLI起動後にPCが落ちると結果コメントが投稿されないまま終了する。この場合も再実行はせず、本人が `result.json` の有無で判断する。

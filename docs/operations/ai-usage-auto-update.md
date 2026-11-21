# Windows AI Usage refresh

Workstream: [agent-controller #333](https://github.com/oimus1976/agent-controller/issues/333), [life-dashboard #235](https://github.com/oimus1976/life-dashboard/issues/235).

The scheduled task attempts a refresh at logon and roughly once an hour while the owner is signed in. A run compares normalized quota and reset values per provider and pool. Identical values skip the build and production update. Missing providers and pools keep their last real values and original observation times. The dashboard may mark those rows stale while an input is unavailable or when the same quota values have not been republished. A file input older than two hours is excluded. The collector uses the actual file capture time for statusline inputs.

The default mode is a preview. It temporarily applies the candidate in a dedicated clean dashboard checkout, runs the declared pnpm 10.4.1 type check, AI Usage tests and static build, and restores its own JSON edit. Preview does not push, access SFTP, register a scheduled task, or publish artifacts. It can be exercised with a synthetic observations file plus the existing dashboard tests.

Explicit apply mode uses the same validation, checks Basic authentication and SFTP before committing, creates a normal fast-forward data-only commit on the approved private main branch, and uploads the validated build. Individual file uploads leave the existing directories in place. It confirms the asset and fixture directory modes are 755 and size-checks uploaded files before publishing index.html. The protected files are checked by metadata only. A publication marker blocks subsequent runs after any incomplete commit, push or deployment. The owner reconciles main and production and decides how to resume.

## Local configuration

Keep the configuration JSON and logs outside the Git checkouts. Use absolute paths. The configuration records local paths and connection identifiers only. Keep credentials in Windows-managed storage or the owner-provisioned SSH identity.

| Property | Value |
| --- | --- |
| dashboard_dir | Dedicated life-dashboard main checkout with installed locked dependencies |
| collector_dir | Verified checkout containing agent_controller.capacity_collect |
| codex_executable | Native Codex executable path |
| claude_statusline | Existing local Claude rate-limit snapshot |
| antigravity_statusline | Existing local Antigravity quota snapshot |
| pnpm_command | Command argument array for pnpm 10.4.1, such as Node executable and the pnpm CLI path |
| state_dir | Dedicated local state folder outside the dashboard checkout |
| openssh_dir | Windows built-in OpenSSH executable directory |
| sftp_target | Owner-approved account and initial domain in user@host form |
| sftp_dashboard_dir | Exact existing remote dashboard directory from the owner deployment runbook |
| sftp_key | Path to the owner-provisioned dedicated identity |
| sftp_host_fingerprint | Independently verified ED25519 host fingerprint |

The task runs with the current logged-in Windows identity. Before activation, verify that this identity can use the exact Git remote and SSH key without prompts. Keep the SSH host key pinned and its private identity outside the repositories. Verify project approval for data-only writes to main, SSH key registration, and recurring deployment. In particular, the existing manual deployment decision must be explicitly superseded for this scoped refresh.

The launcher is scripts/capacity-auto-update.ps1. The task registration script shows its planned action by default. Its explicit Register option requires an approved first live run and leaves any existing task for human reconciliation.

# Antigravity capacity owner-machine pilot

Related: Issue #177, PR #186

## Purpose

Record the bounded owner-machine verification for the Antigravity status-line capacity observer without treating provider UI output, local execution, or operator prose as equivalent to GitHub-hosted CI evidence.

## Verified implementation boundary

PR #186 captures one Antigravity custom `statusLine` JSON payload from stdin, duplicate-key validates the original payload, persists only the capacity-relevant top-level fields (`product`, `version`, `quota`, `status`, `error`), and then reuses the provider-neutral Antigravity capacity parser. Identity, workspace, transcript, conversation, and context fields are discarded before persistence.

The capture artifact records `captured_at`, which proves when the Antigravity TUI delivered the payload to the Controller-owned sink. It does not prove when the provider/backend refreshed the quota value. The pilot therefore ran `/usage` manually immediately before the observed capture.

## Owner-machine environment

- Windows standard user: `WOBBUFFET\agy-agent`
- isolated checkout: `C:\Users\agy-agent\antigravity-work\review-pr186`
- verified PR head before live pilot: `661ad10b0f412ed271f58d2094729a8bbdc29cd1`
- Python: 3.12.10, installed in the `agy-agent` user profile
- Antigravity CLI initially characterized as 1.1.27 and observed during the live pilot as 1.1.28
- paid-credit use remained disabled; `Use AI Credits` was confirmed `off` in the 1.1.28 configuration UI
- telemetry was confirmed `off` in the 1.1.28 configuration UI

## Windows statusLine execution characterization

A direct `statusLine.command` containing the quoted absolute Python executable and script path failed under the Windows command boundary. The CLI reported the quoted executable as not recognized.

The pilot therefore used a temporary `.cmd` wrapper whose only job was to invoke the exact Python interpreter and `scripts/capture_antigravity_statusline.py` with the private capture root/path. The wrapper was first validated with synthetic stdin before being wired into Antigravity.

This wrapper was an owner-machine pilot artifact only; it was not added to the repository and was removed during cleanup.

## Synthetic verification

At exact head `661ad10b0f412ed271f58d2094729a8bbdc29cd1`:

- targeted PR #186 tests: PASS, with the Windows file-symlink case skipped only when the standard user lacked symlink privilege;
- full deterministic unittest discovery: 816 tests PASS, 2 platform/privilege skips;
- dedicated Windows junction regression: 2 tests PASS;
- synthetic capture through the Python sink: PASS;
- synthetic capture through the temporary `.cmd` wrapper: PASS;
- capacity payload preserved multiple quota pools while `email`, `conversation_id`, `transcript_path`, `workspace`, and `context` were not retained;
- checkout remained exact-head and clean after test execution.

## Live Antigravity 1.1.28 observation

After manually opening `/usage`, the live status-line capture produced four distinct quota pools:

- `3p-5h`
- `3p-weekly`
- `gemini-5h`
- `gemini-weekly`

The exact-head observer converted all four to provider-neutral `ProviderCapacityPoolObservation` values with:

- provider: `antigravity`
- source: `PROVIDER_TELEMETRY`
- capacity unit: `fraction`
- reset timestamp present for every pool
- provenance: `antigravity-cli-statusline/1.1.28`

At the observed point, three pools reported remaining capacity `1.0` and `gemini-weekly` reported `0.99230576`. These values are point-in-time telemetry and must not be treated as durable capacity facts after their freshness/reset boundaries.

## Antigravity 1.1.28 settings migration observed during pilot

Launching 1.1.28 rewrote the user settings representation. Compared with the pre-pilot backup, `enableTelemetry` and `allowNonWorkspaceAccess` disappeared from the JSON while the configuration UI showed both telemetry and non-workspace access as `off`. The trusted-workspace list also gained the isolated `review-pr186` checkout after the user explicitly trusted that exact directory.

Because 1.1.28 changed the settings representation, cleanup did not restore the older settings file wholesale. Instead it preserved the migrated 1.1.28 representation and removed only the temporary `statusLine` entry.

## Cleanup result

After the live observation:

- `statusLine` was removed from the current 1.1.28 settings;
- `Use AI Credits` remained absent/off;
- the private capture artifact was deleted;
- the temporary `.cmd` wrapper was deleted;
- the migrated trusted-workspace state was retained.

## CI evidence boundary

GitHub-hosted Actions exact-head execution was unavailable during this work because the account had exhausted its included monthly Actions minutes. Local exact-head execution and the owner-machine live pilot are supplemental verification only and must not be mislabeled as GitHub-hosted CI.

The repository workflow currently requires both:

- Ubuntu/Python 3.12 full unittest discovery;
- Windows/Python 3.12 real junction containment regression.

A separate workstream should provide a zero-paid exact-head fallback for periods when GitHub-hosted minutes are exhausted. Until that authority is explicitly designed, the absence of GitHub-hosted CI remains distinct from code failure and from local PASS.

Ready / merge remain human-final under ADR #90.

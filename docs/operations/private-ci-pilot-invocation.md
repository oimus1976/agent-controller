# Starting the private-CI pilot scripts

Status: operator note ([#327](https://github.com/oimus1976/agent-controller/issues/327)). It changes no authority. Every live step still needs its own human authorization ([rules §8](../governance/rules.md)).

## Rule

Start every pilot script **as a module, from the controller repository root** (the clean canonical tree, for example `C:\Users\c-admin\.codex\worktrees\canonical-main\agent-controller`):

```powershell
Set-Location -LiteralPath '<controller repo root>'
python -m scripts.<module> <arguments>
```

Do not start them by file path. `python scripts\<file>.py` puts `scripts\` first on `sys.path`, so `import agent_controller` fails with `ModuleNotFoundError: No module named 'agent_controller'` before any check runs. This happened on #216 on 2026-09-19 and 2026-11-16; on 2026-11-16 it used up a one-time freeze authorization with no effect.

Before using a one-time authorization, you can check the import without calling `main()`:

```powershell
python -c "import scripts.<module>"
```

## Scripts that need the module form

| Step | Command |
|---|---|
| Pilot identity freeze | `python -m scripts.create_private_ci_pilot_freeze …` |
| Phase 0 | `python -m scripts.collect_private_ci_phase0 …` |
| Phase 0 with target-profile hold | `python -m scripts.collect_private_ci_phase0_with_target_hold …` ([#316](issue-316-deferred-phase0.md)) |
| Phase 1/3 registration plan / apply | `python -m scripts.run_private_ci_live_registration plan` / `apply …` |
| Registration handoff | `python -m scripts.build_private_ci_registration_handoff` |
| Phase 4 | `python -m scripts.run_private_ci_phase4 …` |
| Phase 5 | `python -m scripts.run_private_ci_phase5 …` |

The arguments for each step come from the latest checkpoint on #216 and the script source, not from this table. Do not probe a script with `--help`: `build_private_ci_registration_handoff` takes no arguments, so any invocation starts the real step. Use the import check above instead.

`scripts/retire_private_ci_generation.py` does not import `agent_controller`. The rendered Phase 6 candidate calls it by full path, and that is intended.

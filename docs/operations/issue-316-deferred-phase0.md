# Issue #316 — deferred Phase 0 (fixture-only foundation)

Status: **NON-LIVE / NO OPERATOR HANDOFF / NO LIVE AUTHORITY**.

`agent_controller/private_ci_phase0_deferred.py` stages validated Phase 0 v3
bytes in memory and refuses to write the canonical slot until the supplied
release-and-verify callback returns exactly `True`. It also checks freeze
digest before collection, freeze byte stability after restoration, output
exclusivity, and committed byte readback. Existing production Phase0 CLI and
#305 diagnostic supervisor are **unchanged**.

The fixture callbacks in the tests are **not** WOBBUFFET evidence. A real
combined supervisor is still missing: reviewed non-admin #305 owned target
launcher, broker collection during live HKU hold, independent native
poststate with delayed-start handling, and deterministic #195 human-final
operator-step contract. No one may use this module as authorization to load
a real profile, collect a canonical PASS, register a runner or dispatch.

A next isolated change may wire this primitive only after the live bridge
and human gate can be reviewed together. This patch does not claim #216
Phase 0 readiness.

# Handoff checkpoint template

Post this as a comment on the workstream Issue:

- at the end of a session;
- when stopping for a human decision;
- when handing work to another worker.

A checkpoint helps the next worker find its way. It is never authority: the next worker re-reads every mutable fact it depends on from GitHub or CI.

Label every statement by where its authority comes from. Keep the two first groups apart:

- **Verified:** confirmed from an authoritative source and linked, for example a merge commit, a CI run, or a canonical review.
- **Agent-reported:** anything a worker or provider said that has not been independently confirmed.

Copy the block below:

```text
## Checkpoint <UTC timestamp> — <worker / provider / model> — <workstream Issue>

Verified (with evidence links):
- <fact> — <link to commit / PR / CI run / canonical review evidence>

Agent-reported (not yet verified):
- <claim> — <who said it, where>

Changed / intentionally unchanged:
- <what this session changed; what it deliberately left alone>

Uncertain / blocked:
- <open question or blocker, with the evidence that would resolve it>

Human decision pending:
- <exact decision, bound target (PR/SHA/plan), or "none">

Next worker action:
- <one bounded next step>
- Re-read first: <mutable facts to fetch fresh before acting>

Entry read (self-reported): AGENTS.md / PROJECT_STATUS.md at <commit sha>
```

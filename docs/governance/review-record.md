# Review record

Every PR states who implemented it and who reviewed it, so that review independence can be judged at the human Ready gate ([ADR #199](https://github.com/oimus1976/agent-controller/issues/199), `ai-dev-starter` BASELINE §9).

## Independence levels

- **L0:** self-review by the implementing worker. It never counts as independent review.
- **L1:** fresh-context or adversarial review.
- **L2:** a separate agent or model, or an independently configured reviewer.
- **L3:** a materially different provider or toolchain, plus human final judgment.

## Identity limitation

Most workers post to GitHub through the owner account `oimus1976`. Relayed ChatGPT, Claude, Antigravity, and Jules output all appear under that account, so a GitHub login does not identify the worker.

At the time of writing, the only distinct worker identity is the Codex connector bot `chatgpt-codex-connector[bot]`. Record the worker explicitly, and treat the record as **agent-reported** unless the review was posted by a distinct worker identity. Giving each worker its own GitHub identity is a separate owner decision (see [#256](https://github.com/oimus1976/agent-controller/issues/256)).

## Record

Fill in this block in the PR description, or in a comment for each review round:

```text
Implementation worker: <provider / model / surface>
Reviewer worker:       <provider / model / surface>   (must differ from implementation worker for L1+)
Reviewed exact head:   <40-hex SHA>
Independence level:    L0 | L1 | L2 | L3
Reviewer identity:     distinct GitHub identity <login> | agent-reported via <account>
Result:                clean | findings (<links>) 
```

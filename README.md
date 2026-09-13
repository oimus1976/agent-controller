# agent-controller

Human-on-the-loop controller for orchestrating AI agents through GitHub.

Agent Controller is an experimental, safety-first controller for coordinating bounded work across AI providers while keeping GitHub state and deterministic evidence separate from provider self-reporting.

## Status

This project is under active development. Repository visibility, release, deployment, Ready-for-review transitions, and merge authority remain human-controlled where the project governance requires them.

The repository is currently undergoing a public-readiness audit. See [`docs/PUBLIC_REPOSITORY_READINESS.md`](docs/PUBLIC_REPOSITORY_READINESS.md) for the publication gate and evidence requirements.

## Validation

The deterministic test suite uses Python 3.12:

```text
python -m unittest discover -s tests -v
```

The Windows junction containment regression is also run separately in GitHub Actions on `windows-latest`.

## Trust boundary

Provider completion text, generated artifacts, GitHub publication, CI, independent review, Controller classification, and human approval are distinct facts. A provider saying that work is complete is not by itself authority to merge, release, deploy, or perform another human-final effect.

Do not place credentials, private keys, or unnecessary machine-specific identifiers in public-facing Issues, PRs, logs, or durable evidence. New public-facing infrastructure evidence should use normalized placeholders unless an exact value is materially required for verification.

## License

No open-source license has been selected yet. Public publication remains blocked on an explicit license decision and corresponding repository license file.

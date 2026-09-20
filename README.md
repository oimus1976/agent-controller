# agent-controller

Human-on-the-loop controller for orchestrating AI agents through GitHub.

Agent Controller is an experimental, safety-first controller for coordinating bounded work across AI providers while keeping GitHub state and deterministic evidence separate from provider self-reporting.

## Status

This project is under active development. Repository visibility, release, deployment, Ready-for-review transitions, and merge authority remain human-controlled where the project governance requires them.

The repository is currently undergoing a public-readiness audit. See [`docs/PUBLIC_REPOSITORY_READINESS.md`](docs/PUBLIC_REPOSITORY_READINESS.md) for the publication gate and evidence requirements.

## Validation

The deterministic test suite uses Python 3.12. Install the pinned runtime/test dependencies first:

```text
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The workflow-aware private-CI authority checks use the pinned PyYAML dependency from `requirements.txt`; owner-machine Phase 0/5 tooling must use the same dependency set.

The Windows junction containment regression is also run separately in GitHub Actions on `windows-latest`.

## Trust boundary

Provider completion text, generated artifacts, GitHub publication, CI, independent review, Controller classification, and human approval are distinct facts. A provider saying that work is complete is not by itself authority to merge, release, deploy, or perform another human-final effect.

Do not place credentials, private keys, or unnecessary machine-specific identifiers in public-facing Issues, PRs, logs, or durable evidence. New public-facing infrastructure evidence should use normalized placeholders unless an exact value is materially required for verification.

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE).

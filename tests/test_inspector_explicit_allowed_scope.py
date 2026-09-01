from agent_controller.inspector import evaluate_scope


SMOKE_PATH = "docs/live-jules-e2e-smoke-result.md"


def _file(path: str, *, changes: int = 1) -> dict[str, object]:
    return {"filename": path, "changes": changes}


def test_explicit_allowed_docs_path_is_satisfied() -> None:
    policy = {
        "allowed_paths": [SMOKE_PATH],
        "denied_paths": ["agent_controller/**", "tests/**", ".github/**"],
    }

    assert evaluate_scope([_file(SMOKE_PATH, changes=3)], policy) == "SATISFIED"


def test_docs_path_outside_explicit_allowed_paths_is_violation() -> None:
    policy = {"allowed_paths": [SMOKE_PATH], "denied_paths": []}

    assert evaluate_scope([_file("docs/other.md")], policy) == "VIOLATION"


def test_denied_path_precedes_explicit_allow() -> None:
    policy = {
        "allowed_paths": ["docs/**"],
        "denied_paths": ["docs/private/**"],
    }

    assert evaluate_scope([_file("docs/private/secret.md")], policy) == "VIOLATION"


def test_legacy_generic_docs_only_policy_still_requires_opt_in() -> None:
    policy = {"denied_paths": ["agent_controller/**"], "allow_docs_only": False}

    assert evaluate_scope([_file("docs/readme.md")], policy) == "VIOLATION"


def test_legacy_docs_only_opt_in_still_satisfies() -> None:
    policy = {"denied_paths": ["agent_controller/**"], "allow_docs_only": True}

    assert evaluate_scope([_file("docs/readme.md")], policy) == "SATISFIED"

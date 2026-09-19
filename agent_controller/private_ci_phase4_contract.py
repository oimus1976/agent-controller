from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath


@dataclass(frozen=True, slots=True)
class PrivateCiPilotBinding:
    """Immutable cross-phase identity for one private-CI pilot attempt.

    This object carries identity only. It does not itself prove that any phase
    passed and it carries no mutation authority or reusable credential.
    """

    repository: str
    pull_request_number: int
    target_sha: str
    workflow_sha: str
    workflow_path: str
    runner_id: int
    runner_name: str
    runner_label: str
    environment_generation: str
    runner_root: str
    work_folder: str
    host: str
    broker_identity: str
    target_identity: str


def _plain_nonempty(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _full_lower_sha(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _workflow_path_valid(value: object) -> bool:
    if not _plain_nonempty(value):
        return False
    assert type(value) is str
    if "\\" in value:
        return False
    path = PurePosixPath(value)
    parts = path.parts
    return (
        not path.is_absolute()
        and ".." not in parts
        and len(parts) >= 3
        and parts[:2] == (".github", "workflows")
        and path.suffix in (".yml", ".yaml")
        and str(path) == value
    )


def _windows_root_valid(value: object) -> bool:
    if not _plain_nonempty(value):
        return False
    assert type(value) is str
    path = PureWindowsPath(value)
    return path.is_absolute() and ".." not in path.parts


def _work_folder_valid(value: object) -> bool:
    if not _plain_nonempty(value):
        return False
    assert type(value) is str
    return (
        value not in (".", "..")
        and "/" not in value
        and "\\" not in value
    )


def pilot_binding_reason_codes(binding: object) -> tuple[str, ...]:
    if type(binding) is not PrivateCiPilotBinding:
        return ("PILOT_BINDING_TYPE_INVALID",)

    reasons: list[str] = []

    if (
        not _plain_nonempty(binding.repository)
        or binding.repository.count("/") != 1
        or any(not part for part in binding.repository.split("/"))
    ):
        reasons.append("PILOT_BINDING_REPOSITORY_INVALID")
    if (
        type(binding.pull_request_number) is not int
        or binding.pull_request_number <= 0
    ):
        reasons.append("PILOT_BINDING_PR_NUMBER_INVALID")
    if not _full_lower_sha(binding.target_sha):
        reasons.append("PILOT_BINDING_TARGET_SHA_INVALID")
    if not _full_lower_sha(binding.workflow_sha):
        reasons.append("PILOT_BINDING_WORKFLOW_SHA_INVALID")
    if not _workflow_path_valid(binding.workflow_path):
        reasons.append("PILOT_BINDING_WORKFLOW_PATH_INVALID")
    if type(binding.runner_id) is not int or binding.runner_id <= 0:
        reasons.append("PILOT_BINDING_RUNNER_ID_INVALID")
    if not _plain_nonempty(binding.runner_name):
        reasons.append("PILOT_BINDING_RUNNER_NAME_INVALID")
    if not _plain_nonempty(binding.runner_label):
        reasons.append("PILOT_BINDING_RUNNER_LABEL_INVALID")
    if not _plain_nonempty(binding.environment_generation):
        reasons.append("PILOT_BINDING_ENVIRONMENT_GENERATION_INVALID")
    if not _windows_root_valid(binding.runner_root):
        reasons.append("PILOT_BINDING_RUNNER_ROOT_INVALID")
    if not _work_folder_valid(binding.work_folder):
        reasons.append("PILOT_BINDING_WORK_FOLDER_INVALID")
    if not _plain_nonempty(binding.host):
        reasons.append("PILOT_BINDING_HOST_INVALID")
    if not _plain_nonempty(binding.broker_identity):
        reasons.append("PILOT_BINDING_BROKER_IDENTITY_INVALID")
    if not _plain_nonempty(binding.target_identity):
        reasons.append("PILOT_BINDING_TARGET_IDENTITY_INVALID")
    if (
        _plain_nonempty(binding.broker_identity)
        and _plain_nonempty(binding.target_identity)
        and binding.broker_identity.casefold() == binding.target_identity.casefold()
    ):
        reasons.append("PILOT_BINDING_IDENTITY_SEPARATION_INVALID")

    return tuple(reasons)

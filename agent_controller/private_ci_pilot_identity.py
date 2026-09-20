from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath, PureWindowsPath

import yaml
from yaml.resolver import BaseResolver


PILOT_IDENTITY_FREEZE_SCHEMA = "agent-controller.private-ci-pilot-identity-freeze.v1"
PRIVATE_CI_RUNNER_ROOT_PARENT = r"C:\ProgramData\agent-controller\private-ci"
PRIVATE_CI_WORK_FOLDER = "_work"
PRIVATE_CI_RUNNER_LABEL = "private-ci-windows-pilot"
PRIVATE_CI_TARGET_IDENTITY = "ac-runner"
PRIVATE_CI_HOST = "WOBBUFFET"
PRIVATE_CI_BROKER_IDENTITY = r"WOBBUFFET\c-admin"

HISTORICAL_CONSUMED_RUNNER_NAME = "ac-ci-153d6e1a29fea2cd"
HISTORICAL_CONSUMED_ENVIRONMENT_GENERATION = "ac-pilot-65bbb1dc7c48d6e3"

_RUNNER_NAME = re.compile(r"^ac-ci-[0-9a-f]{16}$")
_GENERATION = re.compile(r"^ac-pilot-[0-9a-f]{16}$")


@dataclass(frozen=True, slots=True)
class PrivateCiPilotIdentityFreeze:
    schema: str
    repository: str
    pull_request_number: int
    target_sha: str
    workflow_sha: str
    workflow_path: str
    runner_name: str
    runner_label: str
    environment_generation: str
    runner_root: str
    work_folder: str
    controller_main_sha: str
    controller_tree: str
    host: str
    broker_identity: str
    target_identity: str


def canonical_runner_root(environment_generation: str) -> str:
    if type(environment_generation) is not str:
        raise ValueError("pilot generation invalid")
    return str(
        PureWindowsPath(PRIVATE_CI_RUNNER_ROOT_PARENT)
        / environment_generation
        / "runner"
    )


def _sha(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _workflow_path(value: object) -> bool:
    if type(value) is not str or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and len(path.parts) >= 3
        and path.parts[:2] == (".github", "workflows")
        and path.suffix in (".yml", ".yaml")
        and str(path) == value
    )


def _windows_absolute(value: object) -> bool:
    if type(value) is not str or not value:
        return False
    path = PureWindowsPath(value)
    return path.is_absolute() and ".." not in path.parts


def pilot_identity_freeze_reason_codes(
    freeze: object,
) -> tuple[str, ...]:
    if type(freeze) is not PrivateCiPilotIdentityFreeze:
        return ("PILOT_FREEZE_TYPE_INVALID",)

    reasons: list[str] = []
    if freeze.schema != PILOT_IDENTITY_FREEZE_SCHEMA:
        reasons.append("PILOT_FREEZE_SCHEMA_INVALID")
    if (
        type(freeze.repository) is not str
        or freeze.repository.count("/") != 1
        or any(not part for part in freeze.repository.split("/"))
    ):
        reasons.append("PILOT_FREEZE_REPOSITORY_INVALID")
    if (
        type(freeze.pull_request_number) is not int
        or freeze.pull_request_number <= 0
    ):
        reasons.append("PILOT_FREEZE_PR_INVALID")
    if not _sha(freeze.target_sha):
        reasons.append("PILOT_FREEZE_TARGET_SHA_INVALID")
    if not _sha(freeze.workflow_sha):
        reasons.append("PILOT_FREEZE_WORKFLOW_SHA_INVALID")
    if not _workflow_path(freeze.workflow_path):
        reasons.append("PILOT_FREEZE_WORKFLOW_PATH_INVALID")
    if (
        type(freeze.runner_name) is not str
        or _RUNNER_NAME.fullmatch(freeze.runner_name) is None
    ):
        reasons.append("PILOT_FREEZE_RUNNER_NAME_INVALID")
    if freeze.runner_name == HISTORICAL_CONSUMED_RUNNER_NAME:
        reasons.append("PILOT_FREEZE_HISTORICAL_RUNNER_REUSE")
    if freeze.runner_label != PRIVATE_CI_RUNNER_LABEL:
        reasons.append("PILOT_FREEZE_RUNNER_LABEL_INVALID")
    if (
        type(freeze.environment_generation) is not str
        or _GENERATION.fullmatch(freeze.environment_generation) is None
    ):
        reasons.append("PILOT_FREEZE_GENERATION_INVALID")
    if (
        freeze.environment_generation
        == HISTORICAL_CONSUMED_ENVIRONMENT_GENERATION
    ):
        reasons.append("PILOT_FREEZE_HISTORICAL_GENERATION_REUSE")
    if (
        type(freeze.environment_generation) is str
        and _GENERATION.fullmatch(freeze.environment_generation)
        and freeze.runner_root
        != canonical_runner_root(freeze.environment_generation)
    ):
        reasons.append("PILOT_FREEZE_RUNNER_ROOT_NOT_CANONICAL")
    elif not _windows_absolute(freeze.runner_root):
        reasons.append("PILOT_FREEZE_RUNNER_ROOT_INVALID")
    if freeze.work_folder != PRIVATE_CI_WORK_FOLDER:
        reasons.append("PILOT_FREEZE_WORK_FOLDER_INVALID")
    if not _sha(freeze.controller_main_sha):
        reasons.append("PILOT_FREEZE_CONTROLLER_MAIN_SHA_INVALID")
    if not _windows_absolute(freeze.controller_tree):
        reasons.append("PILOT_FREEZE_CONTROLLER_TREE_INVALID")
    if freeze.host != PRIVATE_CI_HOST:
        reasons.append("PILOT_FREEZE_HOST_INVALID")
    if freeze.broker_identity != PRIVATE_CI_BROKER_IDENTITY:
        reasons.append("PILOT_FREEZE_BROKER_IDENTITY_INVALID")
    if freeze.target_identity != PRIVATE_CI_TARGET_IDENTITY:
        reasons.append("PILOT_FREEZE_TARGET_IDENTITY_INVALID")
    if freeze.broker_identity.casefold() == freeze.target_identity.casefold():
        reasons.append("PILOT_FREEZE_IDENTITY_SEPARATION_INVALID")
    return tuple(reasons)




_GITHUB_HOSTED_RUNNER = re.compile(
    r"^(ubuntu|windows|macos)-[A-Za-z0-9._-]+$"
)


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ValueError("workflow YAML mapping key is not scalar/hashable") from error
        if duplicate:
            raise ValueError(f"workflow YAML duplicate key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _parse_workflow_jobs(path: str, source: str) -> dict[str, dict[str, object]]:
    try:
        payload = yaml.load(source, Loader=_UniqueKeySafeLoader)
    except (yaml.YAMLError, ValueError) as error:
        raise ValueError(f"workflow YAML invalid: {path}") from error
    if type(payload) is not dict:
        raise ValueError(f"workflow root must be mapping: {path}")
    jobs = payload.get("jobs")
    if type(jobs) is not dict or not jobs:
        raise ValueError(f"workflow jobs mapping missing: {path}")

    parsed: dict[str, dict[str, object]] = {}
    for job_name, job in jobs.items():
        if type(job_name) is not str or not job_name:
            raise ValueError(f"workflow job name invalid: {path}")
        if type(job) is not dict:
            raise ValueError(f"workflow job shape invalid: {path}:{job_name}")
        parsed[job_name] = job
    return parsed


def _static_runs_on(
    *,
    workflow_path: str,
    job_name: str,
    job: dict[str, object],
) -> str:
    if "uses" in job:
        raise ValueError(
            f"reusable workflow job unsupported at pilot boundary: "
            f"{workflow_path}:{job_name}"
        )
    if "runs-on" not in job:
        raise ValueError(
            f"workflow job runs-on missing: {workflow_path}:{job_name}"
        )
    runs_on = job["runs-on"]
    if type(runs_on) is not str or not runs_on.strip():
        raise ValueError(
            f"workflow job runs-on must be static scalar: "
            f"{workflow_path}:{job_name}"
        )
    value = runs_on.strip()
    if "${{" in value:
        raise ValueError(
            f"workflow job runs-on expression unsupported: "
            f"{workflow_path}:{job_name}"
        )
    return value


def validate_pilot_workflow_runner_exclusivity(
    workflow_sources: dict[str, str],
    *,
    trusted_workflow_path: str,
) -> None:
    if (
        type(workflow_sources) is not dict
        or not workflow_sources
        or trusted_workflow_path not in workflow_sources
    ):
        raise ValueError("pilot workflow inventory invalid")

    for path, source in workflow_sources.items():
        if (
            type(path) is not str
            or type(source) is not str
            or not path.startswith(".github/workflows/")
            or not path.endswith((".yml", ".yaml"))
        ):
            raise ValueError("pilot workflow inventory entry invalid")

        jobs = _parse_workflow_jobs(path, source)
        if path == trusted_workflow_path:
            if len(jobs) != 1:
                raise ValueError(
                    "trusted pilot workflow must contain exactly one job"
                )
            job_name, job = next(iter(jobs.items()))
            if _static_runs_on(
                workflow_path=path,
                job_name=job_name,
                job=job,
            ) != PRIVATE_CI_RUNNER_LABEL:
                raise ValueError(
                    "trusted pilot workflow runner binding is not exclusive"
                )
            continue

        for job_name, job in jobs.items():
            value = _static_runs_on(
                workflow_path=path,
                job_name=job_name,
                job=job,
            )
            if (
                value == PRIVATE_CI_RUNNER_LABEL
                or _GITHUB_HOSTED_RUNNER.fullmatch(value) is None
            ):
                raise ValueError(
                    "non-target workflow runner binding is not provably "
                    f"GitHub-hosted: {path}:{job_name}"
                )


def build_fresh_pilot_identity_freeze(
    *,
    repository: str,
    pull_request_number: int,
    target_sha: str,
    workflow_sha: str,
    workflow_path: str,
    nonce: str,
    controller_main_sha: str,
    controller_tree: str,
) -> PrivateCiPilotIdentityFreeze:
    if type(nonce) is not str or re.fullmatch(r"[0-9a-f]{16}", nonce) is None:
        raise ValueError("pilot nonce invalid")
    generation = f"ac-pilot-{nonce}"
    freeze = PrivateCiPilotIdentityFreeze(
        schema=PILOT_IDENTITY_FREEZE_SCHEMA,
        repository=repository,
        pull_request_number=pull_request_number,
        target_sha=target_sha,
        workflow_sha=workflow_sha,
        workflow_path=workflow_path,
        runner_name=f"ac-ci-{nonce}",
        runner_label=PRIVATE_CI_RUNNER_LABEL,
        environment_generation=generation,
        runner_root=canonical_runner_root(generation),
        work_folder=PRIVATE_CI_WORK_FOLDER,
        controller_main_sha=controller_main_sha,
        controller_tree=controller_tree,
        host=PRIVATE_CI_HOST,
        broker_identity=PRIVATE_CI_BROKER_IDENTITY,
        target_identity=PRIVATE_CI_TARGET_IDENTITY,
    )
    reasons = pilot_identity_freeze_reason_codes(freeze)
    if reasons:
        raise ValueError(
            "fresh pilot identity freeze invalid: " + ",".join(reasons)
        )
    return freeze

def pilot_identity_freeze_bytes(
    freeze: PrivateCiPilotIdentityFreeze,
) -> bytes:
    reasons = pilot_identity_freeze_reason_codes(freeze)
    if reasons:
        raise ValueError("pilot identity freeze invalid: " + ",".join(reasons))
    return (
        json.dumps(
            asdict(freeze),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def parse_pilot_identity_freeze_bytes(
    raw: bytes,
) -> PrivateCiPilotIdentityFreeze:
    if type(raw) is not bytes:
        raise ValueError("pilot identity freeze must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("pilot identity freeze JSON invalid") from error
    if (
        type(payload) is not dict
        or set(payload) != set(PrivateCiPilotIdentityFreeze.__dataclass_fields__)
    ):
        raise ValueError("pilot identity freeze shape invalid")
    try:
        freeze = PrivateCiPilotIdentityFreeze(**payload)
    except TypeError as error:
        raise ValueError("pilot identity freeze fields invalid") from error
    if raw != pilot_identity_freeze_bytes(freeze):
        raise ValueError("pilot identity freeze is not canonical")
    return freeze

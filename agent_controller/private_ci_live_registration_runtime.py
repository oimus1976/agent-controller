from __future__ import annotations

import hashlib
import json
import locale
import os
import shutil
import subprocess
import time
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Optional

from agent_controller.operator_step_gate import (
    AUTHORITATIVE_EVIDENCE_ROOT,
    AuthenticatedAstAttestation,
    OperatorGateStatus,
    operator_step_spec_sha256,
)
from agent_controller.private_ci_live_registration import (
    LiveRegistrationBinding,
    LiveRegistrationResult,
    RegistrationExecution,
    RunnerReadback,
    RunnerReadbackFailure,
    build_live_registration_spec,
    frozen_live_registration_binding,
    phase0_evidence_sha256,
    plan_live_registration,
    render_live_registration_candidate,
)
from agent_controller.private_ci_phase0_evidence import (
    EXPECTED_BROKER_IDENTITY,
    EXPECTED_HOST,
)
from agent_controller.private_ci_runner_readback import (
    RunnerSetChangedAcrossSweeps,
    read_all_runner_items,
)

RUNNER_VERSION = "2.337.0"
RUNNER_PACKAGE_URL = (
    "https://github.com/actions/runner/releases/download/v2.337.0/"
    "actions-runner-win-x64-2.337.0.zip"
)
RUNNER_PACKAGE_SHA256 = "1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc"
RUNNER_PACKAGE_FILENAME = f"actions-runner-win-x64-{RUNNER_VERSION}.zip"

PLAN_SCHEMA = "agent-controller.private-ci-live-registration-plan.v1"
RESULT_SCHEMA = "agent-controller.private-ci-live-registration-result.v2"

POST_REGISTRATION_READBACK_MAX_ATTEMPTS = 6
POST_REGISTRATION_READBACK_DELAY_SECONDS = 1.0
POST_REGISTRATION_READBACK_MAX_DELAY_SECONDS = (
    POST_REGISTRATION_READBACK_MAX_ATTEMPTS - 1
) * POST_REGISTRATION_READBACK_DELAY_SECONDS
POST_REGISTRATION_READBACK_MAX_ELAPSED_SECONDS = 15.0


@dataclass(frozen=True, slots=True)
class LiveRegistrationPlan:
    schema: str
    binding: LiveRegistrationBinding
    phase0_evidence_sha256: str
    candidate: str
    candidate_sha256: str
    spec_sha256: str
    runner_version: str
    runner_package_url: str
    runner_package_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "binding": asdict(self.binding),
            "phase0_evidence_sha256": self.phase0_evidence_sha256,
            "candidate": self.candidate,
            "candidate_sha256": self.candidate_sha256,
            "spec_sha256": self.spec_sha256,
            "runner_version": self.runner_version,
            "runner_package_url": self.runner_package_url,
            "runner_package_sha256": self.runner_package_sha256,
        }


def canonical_json_bytes(payload: dict[str, object]) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def plan_bytes(plan: LiveRegistrationPlan) -> bytes:
    return canonical_json_bytes(plan.to_dict())


def plan_sha256(plan: LiveRegistrationPlan) -> str:
    return hashlib.sha256(plan_bytes(plan)).hexdigest()


def build_reviewed_plan(
    *,
    phase0_evidence_bytes: bytes,
    ast_attestation: AuthenticatedAstAttestation,
) -> LiveRegistrationPlan:
    binding = frozen_live_registration_binding()
    candidate = render_live_registration_candidate(binding)
    planned = plan_live_registration(
        binding,
        phase0_evidence_bytes=phase0_evidence_bytes,
        candidate=candidate,
        ast_attestation=ast_attestation,
    )
    if planned.status is not OperatorGateStatus.PASS_TO_OPERATOR:
        reasons = ",".join(planned.reason_codes) or "PLAN_NOT_PASS"
        raise ValueError(f"live registration plan blocked: {reasons}")
    evidence_sha = phase0_evidence_sha256(phase0_evidence_bytes)
    spec = build_live_registration_spec(binding, phase0_evidence_sha256=evidence_sha)
    return LiveRegistrationPlan(
        schema=PLAN_SCHEMA,
        binding=binding,
        phase0_evidence_sha256=evidence_sha,
        candidate=candidate,
        candidate_sha256=planned.candidate_sha256,
        spec_sha256=operator_step_spec_sha256(spec),
        runner_version=RUNNER_VERSION,
        runner_package_url=RUNNER_PACKAGE_URL,
        runner_package_sha256=RUNNER_PACKAGE_SHA256,
    )


def parse_plan_bytes(raw: bytes) -> LiveRegistrationPlan:
    if type(raw) is not bytes:
        raise ValueError("plan must be exact bytes")
    payload = json.loads(raw.decode("utf-8"))
    if type(payload) is not dict or payload.get("schema") != PLAN_SCHEMA:
        raise ValueError("live registration plan schema invalid")
    binding_payload = payload.get("binding")
    if type(binding_payload) is not dict:
        raise ValueError("live registration binding missing")
    binding = LiveRegistrationBinding(**binding_payload)
    plan = LiveRegistrationPlan(
        schema=payload["schema"],
        binding=binding,
        phase0_evidence_sha256=payload["phase0_evidence_sha256"],
        candidate=payload["candidate"],
        candidate_sha256=payload["candidate_sha256"],
        spec_sha256=payload["spec_sha256"],
        runner_version=payload["runner_version"],
        runner_package_url=payload["runner_package_url"],
        runner_package_sha256=payload["runner_package_sha256"],
    )
    if raw != plan_bytes(plan):
        raise ValueError("live registration plan is not canonical")
    return plan


def validate_frozen_plan(
    plan: LiveRegistrationPlan,
    *,
    phase0_evidence_bytes: bytes,
) -> tuple[str, ...]:
    reasons: list[str] = []
    binding = frozen_live_registration_binding()
    if plan.binding != binding:
        reasons.append("PLAN_BINDING_MISMATCH")
    evidence_sha = phase0_evidence_sha256(phase0_evidence_bytes)
    if plan.phase0_evidence_sha256 != evidence_sha:
        reasons.append("PLAN_PHASE0_EVIDENCE_SHA_MISMATCH")
    candidate = render_live_registration_candidate(binding)
    if plan.candidate != candidate:
        reasons.append("PLAN_CANDIDATE_MISMATCH")
    candidate_sha = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    if plan.candidate_sha256 != candidate_sha:
        reasons.append("PLAN_CANDIDATE_SHA_MISMATCH")
    spec = build_live_registration_spec(binding, phase0_evidence_sha256=evidence_sha)
    if plan.spec_sha256 != operator_step_spec_sha256(spec):
        reasons.append("PLAN_SPEC_SHA_MISMATCH")
    if plan.runner_version != RUNNER_VERSION:
        reasons.append("PLAN_RUNNER_VERSION_MISMATCH")
    if plan.runner_package_url != RUNNER_PACKAGE_URL:
        reasons.append("PLAN_RUNNER_PACKAGE_URL_MISMATCH")
    if plan.runner_package_sha256 != RUNNER_PACKAGE_SHA256:
        reasons.append("PLAN_RUNNER_PACKAGE_SHA_MISMATCH")
    return tuple(reasons)


Downloader = Callable[[str, Path], None]
CommandRunner = Callable[..., subprocess.CompletedProcess[bytes | str]]
Sleeper = Callable[[float], None]
MonotonicClock = Callable[[], float]


@dataclass(frozen=True, slots=True)
class NativeTextResult:
    returncode: int
    stdout: str
    stderr: str
    decoding_errors: tuple[str, ...] = ()
    secret_output_redacted: bool = False


def _redact_native_stream(
    value: object,
    *,
    secrets: tuple[str, ...],
) -> tuple[object, bool]:
    if value is None or not secrets:
        return value, False

    redacted = False
    if type(value) is str:
        text = value
        for secret in secrets:
            if secret and secret in text:
                text = text.replace(secret, "***")
                redacted = True
        return text, redacted

    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        encodings = ("utf-8", locale.getpreferredencoding(False))
        for secret in secrets:
            if not secret:
                continue
            seen: set[bytes] = set()
            for encoding in encodings:
                if not encoding:
                    continue
                try:
                    needle = secret.encode(encoding, errors="strict")
                except (UnicodeEncodeError, LookupError):
                    continue
                if not needle or needle in seen:
                    continue
                seen.add(needle)
                if needle in raw:
                    raw = raw.replace(needle, b"***")
                    redacted = True
        return raw, redacted

    text = str(value)
    for secret in secrets:
        if secret and secret in text:
            text = text.replace(secret, "***")
            redacted = True
    return text, redacted


def _decode_native_stream(value: object, *, stream_name: str) -> tuple[str, bool]:
    if value is None:
        return "", False
    if type(value) is str:
        return value, False
    if not isinstance(value, (bytes, bytearray)):
        return str(value), True

    raw = bytes(value)
    encodings = ("utf-8", locale.getpreferredencoding(False))
    seen: set[str] = set()
    for encoding in encodings:
        if not encoding:
            continue
        normalized = encoding.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        try:
            return raw.decode(encoding, errors="strict"), False
        except (UnicodeDecodeError, LookupError):
            continue

    # Preserve ASCII bytes (including any leaked ASCII token) exactly enough for
    # downstream redaction while making undecodable bytes explicit and printable.
    return raw.decode("ascii", errors="backslashreplace"), True


def _default_downloader(url: str, destination: Path) -> None:
    with urllib.request.urlopen(url, timeout=120) as response:
        with destination.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)


def _default_command_runner(*command: str, **kwargs) -> subprocess.CompletedProcess[bytes | str]:
    return subprocess.run(list(command), check=False, **kwargs)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class WindowsEphemeralRegistrationRuntime:
    def __init__(
        self,
        binding: LiveRegistrationBinding,
        *,
        gh_executable: str = "gh.exe",
        command_runner: CommandRunner = _default_command_runner,
        downloader: Downloader = _default_downloader,
        sleeper: Sleeper = time.sleep,
        monotonic_clock: MonotonicClock = time.monotonic,
    ) -> None:
        self.binding = binding
        self.gh_executable = gh_executable
        self.command_runner = command_runner
        self.downloader = downloader
        self.sleeper = sleeper
        self.monotonic_clock = monotonic_clock
        self._last_readback_attempts = 0

    @property
    def runner_root(self) -> Path:
        return Path(self.binding.runner_root)

    @property
    def last_readback_attempts(self) -> int:
        return self._last_readback_attempts

    def _run_text(
        self,
        *command: str,
        cwd: Optional[Path] = None,
        env=None,
        redact_secrets: tuple[str, ...] = (),
        timeout: Optional[float] = None,
    ) -> NativeTextResult:
        completed = self.command_runner(
            *command,
            cwd=None if cwd is None else str(cwd),
            env=env,
            capture_output=True,
            timeout=timeout,
        )
        raw_stdout, stdout_secret_redacted = _redact_native_stream(
            completed.stdout,
            secrets=redact_secrets,
        )
        raw_stderr, stderr_secret_redacted = _redact_native_stream(
            completed.stderr,
            secrets=redact_secrets,
        )
        stdout, stdout_error = _decode_native_stream(
            raw_stdout,
            stream_name="stdout",
        )
        stderr, stderr_error = _decode_native_stream(
            raw_stderr,
            stream_name="stderr",
        )
        decoding_errors = tuple(
            name
            for name, failed in (
                ("stdout", stdout_error),
                ("stderr", stderr_error),
            )
            if failed
        )
        return NativeTextResult(
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            decoding_errors=decoding_errors,
            secret_output_redacted=(
                stdout_secret_redacted or stderr_secret_redacted
            ),
        )

    @staticmethod
    def _require_decoded(completed: NativeTextResult, context: str) -> None:
        if completed.decoding_errors:
            streams = ",".join(completed.decoding_errors)
            raise RuntimeError(f"{context} native output undecodable: {streams}")

    def _require_broker_identity(self) -> None:
        host = self._run_text("hostname.exe")
        self._require_decoded(host, "host readback")
        if host.returncode != 0:
            raise RuntimeError("host readback failed")
        observed_host = host.stdout.strip()
        if observed_host.casefold() != EXPECTED_HOST.casefold():
            raise RuntimeError("host mismatch")

        identity = self._run_text("whoami.exe")
        self._require_decoded(identity, "broker identity readback")
        if identity.returncode != 0:
            raise RuntimeError("broker identity readback failed")
        observed_identity = identity.stdout.strip()
        if observed_identity.casefold() != EXPECTED_BROKER_IDENTITY.casefold():
            raise RuntimeError("broker identity mismatch")

    def _require_local_safety_baseline(self) -> None:
        script = r"""
$ErrorActionPreference = 'Stop'
$TargetName = 'ac-runner'
$Target = Get-LocalUser -Name $TargetName -ErrorAction SilentlyContinue
$TargetEnabled = $false
$TargetAdmin = $false
if ($null -ne $Target) {
    $TargetEnabled = [bool]$Target.Enabled
    $AdminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $AdminGroup = Get-LocalGroup -SID $AdminSid
    $Qualified = "$env:COMPUTERNAME\$TargetName"
    $Members = @(Get-LocalGroupMember -Group $AdminGroup.Name -ErrorAction Stop)
    $TargetAdmin = $null -ne ($Members | Where-Object {
        $_.Name -ieq $Qualified -or $_.Name -ieq $TargetName
    })
}
$RunnerProcesses = @(
    Get-CimInstance Win32_Process -ErrorAction Stop |
        Where-Object { $_.Name -match 'Runner|actions' }
)
$RunnerServices = @(
    Get-CimInstance Win32_Service -ErrorAction Stop |
        Where-Object {
            $_.Name -match 'runner|actions' -or
            $_.DisplayName -match 'runner|actions'
        }
)
$RunnerTasks = @(
    Get-ScheduledTask -ErrorAction Stop |
        Where-Object {
            $_.TaskName -match 'runner|actions' -or
            $_.TaskPath -match 'runner|actions'
        }
)
[ordered]@{
    target_identity_enabled = $TargetEnabled
    target_identity_admin = $TargetAdmin
    runner_process_count = $RunnerProcesses.Count
    runner_service_count = $RunnerServices.Count
    runner_task_count = $RunnerTasks.Count
} | ConvertTo-Json -Compress
""".strip()
        completed = self._run_text(
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        )
        self._require_decoded(completed, "local safety baseline readback")
        if completed.returncode != 0:
            raise RuntimeError("local safety baseline readback failed")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("local safety baseline readback invalid") from error
        if type(payload) is not dict:
            raise RuntimeError("local safety baseline readback shape invalid")
        if payload.get("target_identity_enabled") is not True:
            raise RuntimeError("target identity is not enabled")
        if payload.get("target_identity_admin") is not False:
            raise RuntimeError("target identity is admin or uncertain")
        if payload.get("runner_process_count") != 0:
            raise RuntimeError("runner process drift detected")
        if payload.get("runner_service_count") != 0:
            raise RuntimeError("runner service drift detected")
        if payload.get("runner_task_count") != 0:
            raise RuntimeError("runner task drift detected")

    def _github_runner_items(
        self,
        repository: str,
        *,
        deadline: Optional[float] = None,
    ) -> tuple[dict[str, object], ...]:
        base = f"repos/{repository}/actions/runners?per_page=100"

        def fetch_page(page: int) -> object:
            endpoint = base if page == 1 else f"{base}&page={page}"
            timeout: Optional[float] = None
            if deadline is not None:
                timeout = deadline - self.monotonic_clock()
                if timeout <= 0:
                    raise RunnerReadbackFailure(
                        "RUNNER_READBACK_TIME_BUDGET_EXHAUSTED"
                    )
            try:
                completed = self._run_text(
                    self.gh_executable,
                    "api",
                    endpoint,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as error:
                raise RunnerReadbackFailure(
                    "RUNNER_READBACK_TIME_BUDGET_EXHAUSTED"
                ) from error
            self._require_decoded(completed, "GitHub runner readback")
            if completed.returncode != 0:
                raise RuntimeError("GitHub runner readback failed")
            try:
                return json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                raise RuntimeError("GitHub runner readback invalid JSON") from error

        return read_all_runner_items(fetch_page)

    def _eligible_count(self, repository: str) -> int:
        count = 0
        for raw in self._github_runner_items(repository):
            labels = raw.get("labels")
            if type(labels) is not list:
                raise RuntimeError("GitHub runner labels shape invalid")
            label_names = tuple(
                item.get("name")
                for item in labels
                if type(item) is dict and type(item.get("name")) is str
            )
            if self.binding.runner_label in label_names or raw.get("name") == self.binding.runner_name:
                count += 1
        return count

    @staticmethod
    def _safe_extract(zip_path: Path, destination: Path) -> None:
        with zipfile.ZipFile(zip_path) as archive:
            for info in archive.infolist():
                name = info.filename.replace("\\", "/")
                pure = PurePosixPath(name)
                if pure.is_absolute() or ".." in pure.parts:
                    raise RuntimeError("runner package path traversal blocked")
            archive.extractall(destination)

    def prepare_runner(self, binding: LiveRegistrationBinding) -> None:
        if binding != self.binding:
            raise RuntimeError("runtime binding mismatch")
        self._require_broker_identity()
        self._require_local_safety_baseline()
        if self.runner_root.exists():
            raise RuntimeError("fresh runner root already exists")
        if self._eligible_count(binding.repository) != 0:
            raise RuntimeError("stale eligible runner exists before registration")

        generation_root = self.runner_root.parent
        if generation_root.exists():
            raise RuntimeError("fresh environment generation already exists")
        generation_root.mkdir(parents=True, exist_ok=False)
        self.runner_root.mkdir(exist_ok=False)
        package_path = generation_root / RUNNER_PACKAGE_FILENAME

        self.downloader(RUNNER_PACKAGE_URL, package_path)
        package_sha = _file_sha256(package_path)
        if package_sha != RUNNER_PACKAGE_SHA256:
            raise RuntimeError("runner package digest mismatch")
        self._safe_extract(package_path, self.runner_root)
        package_path.unlink()

        required = (
            self.runner_root / "config.cmd",
            self.runner_root / "run.cmd",
            self.runner_root / "bin" / "Runner.Listener.exe",
        )
        if not all(path.is_file() for path in required):
            raise RuntimeError("runner package extraction incomplete")
        forbidden_state = (
            ".runner",
            ".credentials",
            ".credentials_rsaparams",
            ".service",
            self.binding.work_folder,
        )
        if any((self.runner_root / name).exists() for name in forbidden_state):
            raise RuntimeError("runner root inherited configured state")

    def acquire_registration_token(self, repository: str) -> str:
        if repository != self.binding.repository:
            raise RuntimeError("registration token repository mismatch")
        if self._eligible_count(repository) != 0:
            raise RuntimeError("stale eligible runner exists before registration")
        completed = self._run_text(
            self.gh_executable,
            "api",
            "--method",
            "POST",
            f"repos/{repository}/actions/runners/registration-token",
        )
        self._require_decoded(completed, "registration token acquisition")
        if completed.returncode != 0:
            raise RuntimeError("registration token acquisition failed")
        payload = json.loads(completed.stdout)
        token = payload.get("token") if type(payload) is dict else None
        if type(token) is not str or not token.strip():
            raise RuntimeError("registration token response invalid")
        return token

    def run_registration(
        self,
        binding: LiveRegistrationBinding,
        registration_token: str,
    ) -> RegistrationExecution:
        if binding != self.binding:
            raise RuntimeError("runtime binding mismatch")
        if not (self.runner_root / "config.cmd").is_file():
            raise RuntimeError("config.cmd missing")
        child_env = os.environ.copy()
        child_env["ACTIONS_RUNNER_INPUT_TOKEN"] = registration_token
        repository_url = f"https://github.com/{binding.repository}"
        completed = self._run_text(
            "cmd.exe",
            "/d",
            "/s",
            "/c",
            "config.cmd",
            "--unattended",
            "--url",
            repository_url,
            "--name",
            binding.runner_name,
            "--labels",
            binding.runner_label,
            "--work",
            binding.work_folder,
            "--ephemeral",
            "--disableupdate",
            "--no-default-labels",
            cwd=self.runner_root,
            env=child_env,
            redact_secrets=(registration_token,),
        )
        return RegistrationExecution(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            output_decoding_uncertain=bool(completed.decoding_errors),
            secret_output_redacted=completed.secret_output_redacted,
        )

    def credential_handoff_cleared(
        self,
        binding: LiveRegistrationBinding,
        registration_token: str,
    ) -> bool:
        if binding != self.binding:
            return False
        if os.environ.get("ACTIONS_RUNNER_INPUT_TOKEN") == registration_token:
            return False
        needle = registration_token.encode("utf-8")
        try:
            for path in self.runner_root.rglob("*"):
                if not path.is_file():
                    continue
                with path.open("rb") as handle:
                    while True:
                        chunk = handle.read(1024 * 1024)
                        if not chunk:
                            break
                        if needle in chunk:
                            return False
        except OSError:
            return False
        return True

    def _local_runner_settings(self) -> dict[str, object]:
        settings_path = self.runner_root / ".runner"
        if not settings_path.is_file():
            raise RuntimeError("local runner settings missing")
        payload = json.loads(settings_path.read_text(encoding="utf-8-sig"))
        if type(payload) is not dict:
            raise RuntimeError("local runner settings shape invalid")
        if payload.get("AgentName") != self.binding.runner_name:
            raise RuntimeError("local runner name mismatch")
        if payload.get("WorkFolder") != self.binding.work_folder:
            raise RuntimeError("local runner work folder mismatch")
        if payload.get("Ephemeral") is not True:
            raise RuntimeError("local runner is not ephemeral")
        if payload.get("DisableUpdate") is not True:
            raise RuntimeError("local runner update disablement missing")
        return payload

    def _post_registration_items_are_exact(
        self,
        items: tuple[dict[str, object], ...],
    ) -> bool:
        eligible: list[tuple[dict[str, object], tuple[str, ...]]] = []
        for raw in items:
            labels = raw.get("labels")
            if type(labels) is not list:
                raise RuntimeError("GitHub runner labels shape invalid")
            label_names = tuple(
                item["name"]
                for item in labels
                if type(item) is dict and type(item.get("name")) is str
            )
            if (
                raw.get("name") == self.binding.runner_name
                or self.binding.runner_label in label_names
            ):
                eligible.append((raw, label_names))

        if not eligible:
            return False
        if len(eligible) != 1:
            raise RunnerReadbackFailure("RUNNER_READBACK_ELIGIBLE_COUNT_UNSAFE")

        raw, label_names = eligible[0]
        if (
            raw.get("name") != self.binding.runner_name
            or self.binding.runner_label not in label_names
        ):
            raise RunnerReadbackFailure("RUNNER_READBACK_IDENTITY_MISMATCH")
        return True

    @staticmethod
    def _runner_readbacks(
        items: tuple[dict[str, object], ...],
        binding: LiveRegistrationBinding,
    ) -> tuple[RunnerReadback, ...]:
        result: list[RunnerReadback] = []
        for raw in items:
            labels = raw.get("labels")
            if type(labels) is not list:
                raise RuntimeError("GitHub runner labels shape invalid")
            label_names = tuple(
                item["name"]
                for item in labels
                if type(item) is dict and type(item.get("name")) is str
            )
            result.append(
                RunnerReadback(
                    runner_id=int(raw["id"]),
                    name=str(raw["name"]),
                    status=str(raw["status"]),
                    busy=bool(raw["busy"]),
                    labels=label_names,
                    ephemeral=(
                        True
                        if raw.get("name") == binding.runner_name
                        else None
                    ),
                )
            )
        return tuple(result)

    def read_runners(self, repository: str) -> tuple[RunnerReadback, ...]:
        if repository != self.binding.repository:
            raise RuntimeError("runner readback repository mismatch")
        self._local_runner_settings()
        self._last_readback_attempts = 0
        deadline = (
            self.monotonic_clock()
            + POST_REGISTRATION_READBACK_MAX_ELAPSED_SECONDS
        )

        def sleep_before_retry() -> None:
            remaining = deadline - self.monotonic_clock()
            if remaining <= 0:
                raise RunnerReadbackFailure(
                    "RUNNER_READBACK_TIME_BUDGET_EXHAUSTED"
                )
            self.sleeper(
                min(POST_REGISTRATION_READBACK_DELAY_SECONDS, remaining)
            )

        for attempt in range(1, POST_REGISTRATION_READBACK_MAX_ATTEMPTS + 1):
            self._last_readback_attempts = attempt
            try:
                items = self._github_runner_items(
                    repository,
                    deadline=deadline,
                )
            except RunnerSetChangedAcrossSweeps:
                if attempt == POST_REGISTRATION_READBACK_MAX_ATTEMPTS:
                    raise RunnerReadbackFailure(
                        "RUNNER_READBACK_STABILIZATION_EXHAUSTED"
                    )
                sleep_before_retry()
                continue

            if self._post_registration_items_are_exact(items):
                return self._runner_readbacks(items, self.binding)

            if attempt == POST_REGISTRATION_READBACK_MAX_ATTEMPTS:
                raise RunnerReadbackFailure(
                    "RUNNER_VISIBILITY_STABILIZATION_EXHAUSTED"
                )
            sleep_before_retry()

        raise AssertionError("post-registration readback loop escaped safety bound")


def result_payload(
    *,
    plan: LiveRegistrationPlan,
    plan_sha256_value: str,
    result: LiveRegistrationResult,
    runner_readback_attempts: int = 0,
) -> dict[str, object]:
    if (
        type(runner_readback_attempts) is not int
        or runner_readback_attempts < 0
        or runner_readback_attempts > POST_REGISTRATION_READBACK_MAX_ATTEMPTS
    ):
        raise ValueError("runner readback attempts invalid")
    return {
        "schema": RESULT_SCHEMA,
        "plan_sha256": plan_sha256_value,
        "repository": plan.binding.repository,
        "pull_request_number": plan.binding.pull_request_number,
        "target_sha": plan.binding.target_sha,
        "workflow_sha": plan.binding.workflow_sha,
        "runner_name": plan.binding.runner_name,
        "runner_label": plan.binding.runner_label,
        "environment_generation": plan.binding.environment_generation,
        "candidate_sha256": result.candidate_sha256,
        "status": result.status.value,
        "reason_codes": list(result.reason_codes),
        "child_exit_code": result.child_exit_code,
        "runner_id": result.runner_id,
        "runner_readback_attempts": runner_readback_attempts,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def authoritative_path(filename: str) -> Path:
    if type(filename) is not str or not filename or "/" in filename or "\\" in filename:
        raise ValueError("authoritative filename invalid")
    return Path(AUTHORITATIVE_EVIDENCE_ROOT) / filename

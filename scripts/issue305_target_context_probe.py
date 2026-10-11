"""Prepare one review-only #305 probe; never log on or collect canonical evidence.

The supported Phase 4 launch shape and the unchanged Phase 0 command are reused
at rendering time. Native execution belongs to a later exact owner decision.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess

from agent_controller.private_ci_phase0_collector import _local_probe
from agent_controller.private_ci_phase4_contract import target_launch_lines


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "scripts" / "Issue305-TargetContextProbe.ps1.in"

CHILD = """$ErrorActionPreference='Stop';$i=[Security.Principal.WindowsIdentity]::GetCurrent();$p=[Security.Principal.WindowsPrincipal]::new($i);if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 3};[Console]::Out.WriteLine(('{0}|{1}|{2}|{3}'-f $PID,$i.User.Value,$i.Name,$PSVersionTable.PSVersion));$s=[IO.StreamReader]::new([Console]::OpenStandardInput());$r=$s.ReadLineAsync();if(!$r.Wait(60000)){exit 4};if($r.Result-ne'RELEASE'){exit 5};exit 0"""


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def broker_command() -> str:
    commands = []

    def capture(*command):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    _local_probe(capture, "ac-runner")
    return commands[0][-1]


def render() -> bytes:
    # Same creation-handle preserving Process.Start shape; redirected stdin is
    # the one-purpose lease/release extension, requiring a NEW #195 exception.
    launch = "\n".join(target_launch_lines(
        "Target", file_name="$Plan.executable", arguments="$TargetArguments",
        user_name="ac-runner", domain="$Plan.host", password="$Password",
        load_user_profile=True, working_directory="$Plan.working_directory",
        redirect_output=True,
    ))
    # target_launch_lines quotes domains, because its production callers have
    # fixed literal hosts. Here the fresh plan is validated before substitution.
    launch = launch.replace("Domain = '$Plan.host'", "Domain = $Plan.host")
    launch = launch.replace("RedirectStandardOutput = $true;", "RedirectStandardInput = $true; RedirectStandardOutput = $true;")
    source = TEMPLATE.read_text(encoding="utf-8")
    source = source.replace("__TARGET_SOURCE__", CHILD.replace("'", "''"))
    source = source.replace("__BROKER_COMMAND_B64__", base64.b64encode(broker_command().encode("utf-16-le")).decode())
    source = source.replace("__TARGET_LAUNCH__", launch)
    if "__TARGET_" in source or "__BROKER_" in source:
        raise ValueError("unresolved renderer token")
    return source.replace("\r\n", "\n").encode("utf-8")


def design_plan() -> dict:
    raw = render()
    windows = raw.replace(b"\n", b"\r\n")
    return {
        "schema": "issue305.target-context-design.v1",
        "authority": "DESIGN_FIXTURE_REVIEW_ONLY",
        "directive_comment": 6098097114,
        "candidate_lf": {"sha256": digest(raw), "size": len(raw)},
        "candidate_crlf": {"sha256": digest(windows), "size": len(windows)},
        "target_command": {"sha256": digest(CHILD.encode()), "size": len(CHILD.encode())},
        "broker_command": {"sha256": digest(broker_command().encode()), "size": len(broker_command().encode())},
        "deadlines_seconds": {"startup": 10, "broker_probe": 12, "worker_release_signal": 25, "worker_report": 15, "owned_exit": 5, "independent_readback": 8, "child_self_lease": 60},
        "live_binding": None,
        "decision_a": False,
        "decision_b": False,
        "live_plan_schema": {
            "schema": "issue305.target-context-live.v1",
            "required": ["host", "broker_identity", "target_sid", "profile_path", "executable", "executable_sha256", "working_directory", "candidate_sha256", "candidate_size", "decision_a", "decision_b", "not_before_utc", "expires_utc"],
            "target_account": "ac-runner",
            "working_directory": "exact executable directory (trusted Windows System32)",
            "window_max_seconds": 600,
        },
        "allowed_effects": ["one target credential/profile-loading fixed child", "one short broker launcher retaining the target creation handle", "unchanged broker Phase 0 local policy command", "stdin release or kill only retained owned processes", "independent bounded poststate observation"],
        "forbidden_effects": ["canonical Phase 0/freeze", "runner/dispatch/target repository code", "direct registry load/unload", "elevation", "policy/account/group/ACL/service/task modification", "credential logging", "#302 or consumed authority reuse"],
        "partial_start_rule": "Supervisor timeout/unknown creation always STOP_PARTIAL_PROFILE_STATE, even if one immediate postread is empty; a delayed OS logon is not disproved by that read.",
    }


def write_exclusive(path: Path, raw: bytes) -> None:
    with path.open("xb") as output:
        output.write(raw)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True, type=Path)
    options = parser.parse_args()
    # Exclusive directory and files. These are review artifacts, never the
    # canonical handoff paths. No credential, Windows API or target read here.
    options.output_directory.mkdir(parents=True, exist_ok=False)
    write_exclusive(options.output_directory / "Issue305-TargetContextProbe.ps1", render())
    write_exclusive(options.output_directory / "design-plan.json", (json.dumps(design_plan(), indent=2) + "\n").encode())
    print("REVIEW_ARTIFACTS_ONLY_NO_TARGET_STARTED")


if __name__ == "__main__":
    main()

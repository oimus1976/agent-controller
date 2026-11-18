"""Prepare an hourly AI Usage update; publishing requires explicit --apply."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

OBS = "client/src/data/ai-usage.observations.json"
REPO = "https://github.com/oimus1976/life-dashboard.git"
PROVIDERS = ("claude-code", "codex", "antigravity")
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
BASIC_URL = "https://oimus.net/dashboard/"
LOG = logging.getLogger(__name__)


def run(argv, cwd, *, data=None, ok=(0,), env=None):
    result = subprocess.run(
        argv, cwd=cwd, input=data, encoding="utf-8", errors="replace",
        capture_output=True, timeout=900, env=env,
    )
    if result.returncode not in ok:
        # Diagnostics for the collector and transport can contain private paths.
        raise RuntimeError(f"{Path(argv[0]).stem} step failed (exit {result.returncode})")
    return result


def records(document):
    if document.get("document_kind") != "ai-usage-observations" or document.get("version") != "1.0":
        raise ValueError("Unexpected observations document")
    rows = document["observations"]
    keys = {(row["provider"], row["capacity_pool"]) for row in rows}
    if len(keys) != len(rows) or any(provider not in PROVIDERS for provider, _ in keys):
        raise ValueError("Unexpected or duplicate observation key")
    return rows


def timestamp(when):
    return when.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def merge_observations(old, new, captured_at):
    """Retain missing pools. Use capture time for file-backed observations."""
    indexed = {(row["provider"], row["capacity_pool"]): row for row in records(old)}
    updated = dict(indexed)
    changed = False
    quota_fields = ("remaining_fraction", "reset_at", "availability", "capacity_unit")
    for row in records(new):
        provider = row["provider"]
        if provider not in captured_at:
            continue
        observed_at = timestamp(captured_at[provider])
        key = (provider, row["capacity_pool"])
        previous = indexed.get(key)
        if previous is not None and observed_at <= previous["observed_at"]:
            continue
        if previous is None or any(previous[field] != row[field] for field in quota_fields):
            changed = True
        updated[key] = {
            **row, "observed_at": observed_at,
            "source": {**row["source"], "last_verified_at": observed_at},
        }
    if not changed:
        return None
    return {**old, "observations": [updated[key] for key in sorted(updated)]}


def collect(config, scratch):
    now = datetime.now(timezone.utc)
    captured = {"codex": now}
    args = [
        sys.executable, "-m", "agent_controller.capacity_collect", "--codex-app-server",
        "--codex-command", config["codex_executable"], "--out", str(scratch / "observations.json"),
    ]
    for provider, config_key, option in (
        ("claude-code", "claude_statusline", "--claude-code-statusline"),
        ("antigravity", "antigravity_statusline", "--antigravity-statusline"),
    ):
        source = Path(config[config_key])
        try:
            first = source.stat()
            when = datetime.fromtimestamp(first.st_mtime, timezone.utc)
            if not now - timedelta(hours=2) <= when <= now:
                continue
            copy = scratch / (provider + ".json")
            shutil.copyfile(source, copy)
            last = source.stat()
            if (first.st_mtime_ns, first.st_size) != (last.st_mtime_ns, last.st_size):
                continue
        except (FileNotFoundError, PermissionError):
            continue
        captured[provider] = when
        args.extend([option, str(copy)])
    result = run(args, Path(config["collector_dir"]), ok=(0, 1))
    if result.returncode != 0:
        raise RuntimeError("No provider observation was available")
    document = json.loads((scratch / "observations.json").read_bytes())
    captured["codex"] = datetime.now(timezone.utc)
    return document, captured


def git(directory, *args):
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
    return run(["git", *args], directory, env=env).stdout.strip()


def current_main(directory, *, apply):
    if git(directory, "remote", "get-url", "origin") != REPO:
        raise RuntimeError("Unexpected dashboard remote")
    if git(directory, "branch", "--show-current") != "main":
        raise RuntimeError("The dedicated dashboard checkout must be on main")
    if git(directory, "status", "--porcelain"):
        raise RuntimeError("The dashboard checkout must be clean, including the Git index")
    if apply:
        git(directory, "fetch", "origin", "main")
        git(directory, "merge", "--ff-only", "origin/main")
    head = git(directory, "rev-parse", "HEAD")
    if head != git(directory, "rev-parse", "origin/main"):
        raise RuntimeError("HEAD differs from the fetched origin/main")
    return head


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_check(url):
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    try:
        response = urllib.request.build_opener(NoRedirect()).open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.code, "WWW-Authenticate" in response.headers


def http_preflight():
    if http_check(BASIC_URL) != (401, True) or http_check(BASIC_URL + ".htpasswd")[0] not in (403, 404):
        raise RuntimeError("Production authentication preflight failed")


def files_for_upload(dist):
    if {p.name for p in dist.iterdir()} != {"assets", "fixtures", "index.html"}:
        raise RuntimeError("Unexpected top-level build output")
    if not (dist / "assets").is_dir() or not (dist / "fixtures").is_dir():
        raise RuntimeError("Required build directories are missing")
    relative = []
    for path in sorted(dist.rglob("*")):
        if path.is_symlink() or path.is_junction() or not ASSET_NAME.fullmatch(path.name):
            raise RuntimeError("Build contains a link or unsupported name")
        if path.is_dir():
            if path.parent != dist:
                raise RuntimeError("Unexpected nested build directory")
        elif path.is_file():
            relative.append(path.relative_to(dist).as_posix())
        else:
            raise RuntimeError("Unexpected build file type")
    if "index.html" not in relative or not any(name.startswith("assets/") and name.endswith(".js") for name in relative):
        raise RuntimeError("Required build files are missing")
    return [name for name in relative if name != "index.html"] + ["index.html"]


def sftp_remote_path(config):
    path = config["sftp_dashboard_dir"]
    if not re.fullmatch(r"(?:/[A-Za-z0-9][A-Za-z0-9._-]*)+/dashboard", path):
        raise RuntimeError("Invalid approved remote dashboard path")
    return path


def sftp_commands(config, directory, commands):
    ssh_dir = Path(config["openssh_dir"])
    return run([
        str(ssh_dir / "sftp.exe"), "-oBatchMode=yes", "-oPreferredAuthentications=publickey",
        "-oIdentitiesOnly=yes", "-oIdentityAgent=none", "-oStrictHostKeyChecking=yes",
        "-oHostKeyAlgorithms=ssh-ed25519",
        "-oConnectTimeout=12", "-i", config["sftp_key"], "-b", "-", config["sftp_target"],
    ], directory, data="\n".join([f'cd "{sftp_remote_path(config)}"', "pwd", *commands, "bye"]) + "\n").stdout


def mode_map(output, remote):
    if f"Remote working directory: {remote}" not in output.splitlines():
        raise RuntimeError("SFTP did not verify the expected remote directory")
    rows = {}
    for line in output.splitlines():
        fields = line.split(maxsplit=8)
        if len(fields) != 9 or not re.fullmatch(r"[dl-][rwxstST-]{9}[+@.]?", fields[0]):
            continue
        name = fields[-1].split(" -> ", 1)[0].rsplit("/", 1)[-1]
        rows[name] = (fields[0][:10], fields[4])
    return rows


def verify_server(config, dist, relative):
    remote = sftp_remote_path(config)
    target = config["sftp_target"]
    if not re.fullmatch(r"[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+", target):
        raise RuntimeError("Invalid SFTP destination")
    host = target.split("@")[1]
    keygen = str(Path(config["openssh_dir"]) / "ssh-keygen.exe")
    found = run([keygen, "-F", host], dist).stdout
    keys = [line for line in found.splitlines() if " ssh-ed25519 " in line]
    fingerprints = run([keygen, "-lf", "-"], dist, data="\n".join(keys) + "\n").stdout.split()
    if not keys or fingerprints.count(config["sftp_host_fingerprint"]) != len(keys):
        raise RuntimeError("SFTP host key is not pinned to the configured fingerprint")
    root = mode_map(sftp_commands(config, dist, ["ls -la ."]), remote)
    for name in (".htaccess", ".htpasswd", "index.html"):
        if not root.get(name, ("", ""))[0].startswith("-"):
            raise RuntimeError(f"Expected regular remote file: {name}")
    for folder in ("assets", "fixtures"):
        if root.get(folder, ("", ""))[0] != "drwxr-xr-x":
            raise RuntimeError(f"Remote {folder} is not a 755 directory")
        listing = mode_map(sftp_commands(config, dist, [f"ls -la {folder}/"]), remote)
        for path in relative:
            if path.startswith(folder + "/") and not listing.get(Path(path).name, ("-", ""))[0].startswith("-"):
                raise RuntimeError(f"Remote destination is not a regular file: {path}")
    return root


def publish_files(config, dist, relative, original):
    remote = sftp_remote_path(config)
    # Individual puts preserve the already-verified 755 directories.
    sftp_commands(config, dist, [f'put "{name}" "{name}"' for name in relative[:-1]])
    for folder in ("assets", "fixtures"):
        listing = mode_map(sftp_commands(config, dist, [f"ls -la {folder}/"]), remote)
        for name in (value for value in relative if value.startswith(folder + "/")):
            entry = listing.get(Path(name).name, ("", ""))
            if not entry[0].startswith("-") or entry[1] != str((dist / name).stat().st_size):
                raise RuntimeError(f"SFTP size mismatch: {name}")
    current = mode_map(sftp_commands(config, dist, ["ls -la ."]), remote)
    for folder in ("assets", "fixtures"):
        if current.get(folder, ("", ""))[0] != "drwxr-xr-x":
            raise RuntimeError(f"Remote {folder} mode changed before index publish")
    if any(current.get(name) != original[name] for name in (".htaccess", ".htpasswd", "index.html")):
        raise RuntimeError("Remote index or authentication metadata unexpectedly changed")
    final = mode_map(sftp_commands(config, dist, ['put "index.html" "index.html"', "ls -la ."]), remote)
    if final.get("index.html", ("", ""))[1] != str((dist / "index.html").stat().st_size):
        raise RuntimeError("Remote index size differs")
    if any(final.get(name) != current[name] for name in (".htaccess", ".htpasswd", "assets", "fixtures")):
        raise RuntimeError("Protected metadata changed")
    http_preflight()
    js = next(name for name in relative if name.startswith("assets/") and name.endswith(".js"))
    if http_check(BASIC_URL + js) != (401, True) or http_check("https://oimus.net/") != (200, False):
        raise RuntimeError("Post-deploy HTTP checks failed")


def perform(config, *, apply, candidate_file=None):
    directory = Path(config["dashboard_dir"]).resolve()
    state = Path(config["state_dir"]).resolve()
    if state == directory or state.is_relative_to(directory):
        raise RuntimeError("State directory must be outside the dashboard checkout")
    pnpm = config["pnpm_command"]
    collector_dir = Path(config["collector_dir"])
    if not collector_dir.is_dir():
        raise RuntimeError("Collector checkout is unavailable")
    state.mkdir(parents=True, exist_ok=True)
    pending = state / "publication-pending.json"
    lock = state / "run.lock"
    # Exclusive creation prevents concurrent checkouts and publishes. Retain a
    # crash marker until the owner has reconciled any interrupted run.
    lock.touch(exist_ok=False)
    try:
        if pending.exists():
            raise RuntimeError("Prior publication is unresolved; check main and production before resuming")
        head = current_main(directory, apply=apply)
        target = directory / OBS
        original = target.read_bytes()
        old = json.loads(original)
        with tempfile.TemporaryDirectory(prefix="ai-usage-", dir=state) as tmp:
            if candidate_file is None:
                fresh, captured = collect(config, Path(tmp))
            else:
                if apply:
                    raise RuntimeError("Fixture input is permitted only for local preview")
                fresh = json.loads(candidate_file.read_bytes())
                captured = {p: datetime.now(timezone.utc) for p in PROVIDERS}
            candidate = merge_observations(old, fresh, captured)
        if candidate is None:
            LOG.info("SKIP: no quota or reset changes")
            return
        if run([*pnpm, "--version"], directory).stdout.strip() != "10.4.1":
            raise RuntimeError("The dashboard build requires pnpm 10.4.1")
        candidate_bytes = (json.dumps(candidate, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        target.write_bytes(candidate_bytes)
        try:
            for command in ("check", "test:ai-usage", "build:static"):
                run([*pnpm, "run", command], directory)
                LOG.info("PASS: pnpm %s", command)
            dist = directory / "dist/public"
            relative = files_for_upload(dist)
            if target.read_bytes() != candidate_bytes:
                raise RuntimeError("The tested candidate was modified")
            if git(directory, "status", "--porcelain") != "M " + OBS:
                raise RuntimeError("Unexpected tracked or untracked checkout changes")
            if not apply:
                LOG.info("PASS: preview complete; dashboard checkout restored, build retained")
                return
            http_preflight()
            root = verify_server(config, dist, relative)
            if git(directory, "rev-parse", "HEAD") != head or git(directory, "diff", "--cached", "--name-only"):
                raise RuntimeError("Dashboard HEAD or staging area changed after validation")
            pending.write_text(json.dumps({"previous_head": head, "stage": "before_commit"}) + "\n", encoding="utf-8")
            git(directory, "commit", "--only", "-m", "data: refresh AI usage observations", "--", OBS)
            commit = git(directory, "rev-parse", "HEAD")
            if git(directory, "rev-parse", "HEAD^") != head or git(directory, "diff-tree", "--no-commit-id", "--name-only", "-r", commit) != OBS:
                raise RuntimeError("The automation commit must change only the validated observations")
            pending.write_text(json.dumps({"commit": commit, "stage": "before_push"}) + "\n", encoding="utf-8")
            if target.read_bytes() != candidate_bytes or git(directory, "status", "--porcelain"):
                raise RuntimeError("Dashboard contents changed after committing the candidate")
            git(directory, "push", "origin", "HEAD:refs/heads/main")
            expected = f"{commit}\trefs/heads/main"
            if git(directory, "ls-remote", "origin", "refs/heads/main") != expected:
                raise RuntimeError("Remote main does not match the tested commit")
            pending.write_text(json.dumps({"commit": commit, "stage": "production_upload"}) + "\n", encoding="utf-8")
            LOG.info("PASS: data-only main update verified at %s", commit)
            publish_files(config, dist, relative, root)
            pending.unlink()
            LOG.info("PASS: published observations and verified deployment at %s", commit)
        finally:
            if not pending.exists() and git(directory, "rev-parse", "HEAD") == head:
                # Restore only our own preview bytes; avoid overwriting a concurrent edit.
                if target.read_bytes() == candidate_bytes:
                    target.write_bytes(original)
    finally:
        lock.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--apply", action="store_true", help="publish to the approved live targets")
    parser.add_argument("--fixture", type=Path, help="use synthetic observations for a local preview")
    parser.add_argument("--log-file", type=Path)
    args = parser.parse_args()
    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        if args.log_file is not None:
            handlers.append(logging.FileHandler(args.log_file, encoding="utf-8"))
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", handlers=handlers)
        perform(json.loads(args.config.read_bytes()), apply=args.apply, candidate_file=args.fixture)
    except (KeyError, ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        LOG.error("STOP: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

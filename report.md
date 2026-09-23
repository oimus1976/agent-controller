exact commit reviewed: e6989cef53c7004999679d9ef947591240fa7dec

findings classified P1 / P2 / P3:
P1-B (Caller-controlled authority/TOCTOU path replacement)

exact file/line or symbol for every finding:
File: `agent_controller/private_ci_consumption_marker.py`
Symbol: `_windows_powershell_env`
Lines: 148-154
```python
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() != "PSMODULEPATH"
    }
    env.update(updates)
```

concrete failure/exploit path:
1. Environment variables on Windows are case-insensitive, but Python's `os.environ.items()` yields the case-preserved strings.
2. A malicious caller sets the environment variable `target_marker_path` (or `target_acl_path`) in lowercase.
3. `_windows_powershell_env` preserves this lowercase key in the new `env` dictionary.
4. `env.update({"TARGET_MARKER_PATH": str(path)})` inserts the correct path using uppercase.
5. The `env` dictionary now contains both `target_marker_path=malicious_path` and `TARGET_MARKER_PATH=real_path`.
6. When `subprocess.run` executes `powershell.exe`, Windows maps the duplicate keys into the environment block. `powershell.exe` performs case-insensitive lookups (`$env:TARGET_MARKER_PATH`) and can resolve to the attacker-controlled `target_marker_path` instead of the one provided by Python.
7. This allows the attacker to bypass the ACL installation on the real marker and apply it to an arbitrary file, leading to TOCTOU/path replacement or forging authority.

whether an existing test catches it:
No. The existing tests do not catch this. On Linux, `install_protected_marker_acl` is globally mocked in the `setUp` of `PrivateCiPhase7ClassifierRedTests`. On Windows, the real integration tests do not attempt to inject a case-mismatched environment variable to simulate this caller-controlled payload.

missing regression test, if any:
A regression test on Windows (or synthesized on Linux) that sets `target_marker_path` and `target_acl_path` in `os.environ` before invoking `install_protected_marker_acl` and `read_consumption_acl_state`, to assert that the exact intended file is modified/read rather than the injected path.

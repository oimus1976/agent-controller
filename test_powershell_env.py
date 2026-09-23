import os
from agent_controller.private_ci_consumption_marker import _windows_powershell_env

os.environ["target_acl_path"] = "malicious_inherited"
os.environ["TARGET_ACL_PATH"] = "malicious_inherited2"
os.environ["psmodulepath"] = "bad_module_path"
os.environ["PSModulePath"] = "bad_module_path2"
os.environ["other_var"] = "safe"

env = _windows_powershell_env(target_acl_path="safe_target")
print("Environment keys:")
for k, v in env.items():
    print(f"{k}={v}")

try:
    _windows_powershell_env(target_acl_path="safe_target", TARGET_ACL_PATH="safe_target2")
    print("FAILED: Did not raise ValueError on duplicate case-insensitive keys")
except ValueError as e:
    print(f"SUCCESS: Raised ValueError on duplicate case-insensitive keys: {e}")

import subprocess
env = {"target_acl_path": "malicious", "TARGET_ACL_PATH": "safe"}
# Simulation of the Windows behavior - the environment dictionary construction
env_from_os = {"target_acl_path": "malicious"}
new_env = {key: value for key, value in env_from_os.items() if key.upper() != "PSMODULEPATH"}
new_env.update({"TARGET_ACL_PATH": "safe"})
print(new_env)

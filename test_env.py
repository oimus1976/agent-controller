import subprocess
env = {"target_acl_path": "malicious", "TARGET_ACL_PATH": "safe"}
try:
    subprocess.run(["env"], env=env)
except Exception as e:
    print(e)

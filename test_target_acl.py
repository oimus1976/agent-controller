import os

env = {
    key: value
    for key, value in {"target_acl_path": "malicious"}.items()
    if key.upper() != "PSMODULEPATH"
}
env.update({"TARGET_ACL_PATH": "safe"})
print("Environment dictionary constructed:", env)

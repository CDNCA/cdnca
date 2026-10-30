#!/usr/bin/env python3
"""Install/check independent certificate runtime keys without changing base state.

The release owner holds the management lock and installs the service wiring.
This helper never starts services, registers a CA account or changes the DB.
Partial state is retained for recovery, never overwritten or rotated.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import sys

spec = importlib.util.spec_from_file_location("native_control_runtime", Path(__file__).with_name("configure-control-runtime.py"))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def certificate_runtime_environment(email, keys, existing):
    if (not isinstance(email, str) or len(email) > 254 or
            not re.fullmatch(r"[A-Za-z0-9_%+.-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}", email) or
            ".." in email or email.startswith(".") or ".@" in email or
            email.lower().endswith((".local", ".localhost", ".invalid", ".test"))):
        raise ValueError("a certificate contact email with a public domain is required")
    decoded = [base64.b64decode(key, validate=True) for key in keys]
    if (len(keys) != 3 or len(set(keys)) != 3 or
            any(len(value) != 32 or base64.b64encode(value).decode() != keys[index] for index, value in enumerate(decoded)) or
            any(key in value for key in keys for value in existing.values())):
        raise ValueError("certificate keys must be independent canonical 32-byte values")
    return {
        "ACME_RUNTIME_ENABLED": "true",
        "ACME_DIRECTORY_URL": "https://acme-v02.api.letsencrypt.org/directory",
        "ACME_CONTACTS": "mailto:" + email,
        "ACME_WRAPPING_KEY_ID": "native-certificate-wrapping-v1",
        "ACME_WRAPPING_KEY_BASE64": keys[0],
        "ACME_DNS_HANDLE_ACTIVE_KEY_ID": "native-acme-dns-handle-v1",
        "ACME_DNS_HANDLE_ACTIVE_KEY_BASE64": keys[1],
        "CERTIFICATE_PUBLICATION_CURSOR_ACTIVE_KEY_ID": "native-certificate-cursor-v1",
        "CERTIFICATE_PUBLICATION_CURSOR_KEYS_JSON": json.dumps({"native-certificate-cursor-v1": keys[2]}, separators=(",", ":")),
    }


def native_certificate_runtime(action, email):
    if action not in ("install", "check"):
        raise ValueError("expected install or check")
    runtime.native_control_runtime("check")
    inputs = {name: runtime.native_runtime_read(runtime.CONTROL / name)
              for name in ("control.env", "runtime-extra.env", "runtime-receipt.json")}
    base = runtime.native_runtime_env(inputs["control.env"])
    extra = runtime.native_runtime_env(inputs["runtime-extra.env"])
    if any(name.startswith(("ACME_", "CERTIFICATE_PUBLICATION_")) for name in (*base, *extra)):
        raise ValueError("existing certificate configuration requires explicit recovery")
    directory = runtime.CONTROL / "certificate-runtime"
    paths = {"environment": directory / "environment.env", "receipt": directory / "receipt.json"}
    existing = directory.exists() or directory.is_symlink()
    if existing:
        runtime.native_runtime_directory(directory, 0o700)
        if set(directory.iterdir()) != set(paths.values()):
            raise ValueError("partial or unknown certificate runtime state")
        stored = {name: runtime.native_runtime_read(path) for name, path in paths.items()}
        current = runtime.native_runtime_env(stored["environment"])
        cursor = json.loads(current["CERTIFICATE_PUBLICATION_CURSOR_KEYS_JSON"], object_pairs_hook=runtime.native_runtime_pairs)
        if set(cursor) != {"native-certificate-cursor-v1"}:
            raise ValueError("certificate cursor key mismatch")
        keys = [current["ACME_WRAPPING_KEY_BASE64"], current["ACME_DNS_HANDLE_ACTIVE_KEY_BASE64"], cursor["native-certificate-cursor-v1"]]
    else:
        if action == "check":
            raise ValueError("certificate runtime is not installed")
        keys = [base64.b64encode(secrets.token_bytes(32)).decode() for _ in range(3)]
    env = certificate_runtime_environment(email, keys, dict(base, **extra))
    contents = {"environment": "".join(f"{name}='{env[name]}'\n" for name in sorted(env)).encode()}
    receipt = {"schema": "cdnca.native-certificate-runtime/v1", "installation_id": base["CONTROL_INSTALLATION_ID"],
               "inputs_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in inputs.items()},
               "environment_sha256": hashlib.sha256(contents["environment"]).hexdigest()}
    contents["receipt"] = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
    if existing:
        if stored != contents:
            raise ValueError("certificate runtime differs; no existing state was changed")
        return
    directory.mkdir(mode=0o700)
    descriptor = os.open(runtime.CONTROL, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    for name in ("receipt", "environment"):
        runtime.native_runtime_write(paths[name], contents[name], 0o600)


def native_certificate_runtime_main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("install", "check"):
        raise ValueError("usage: configure-certificate-runtime.py install|check CONTACT_EMAIL")
    if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("certificate runtime configuration requires Linux amd64 root")
    os.umask(0o077)
    native_certificate_runtime(sys.argv[1], sys.argv[2])
    print(json.dumps({"status": "passed", "action": sys.argv[1],
                      "environment_file": str(runtime.CONTROL / "certificate-runtime" / "environment.env")}))


if __name__ == "__main__":
    try:
        native_certificate_runtime_main()
    except (OSError, ValueError, KeyError, TypeError, runtime.subprocess.SubprocessError):
        print("native certificate runtime configuration failed; existing state preserved", file=sys.stderr)
        sys.exit(1)

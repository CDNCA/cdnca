#!/usr/bin/env python3
"""Root-operated, one-shot enablement of the DNS write runtime on an installed console.

Fresh installs get DNS_RECONCILE_* / CNAME_ALLOCATION_* in control.env from
install-control.sh write_environment. Upgrades never rewrite /etc (the native
upgrade runner is ProtectSystem=strict) and control.env is pinned by
runtime-receipt.json, so existing consoles get a separate root-only env file
plus a systemd drop-in that loads it after the unit's own EnvironmentFile lines.

  check     report the state and the planned settings (secret redacted)
  apply     write dns-runtime.env (0400, kept forever: its CNAME key names
            allocated hostnames) and the drop-in, restart control-api, probe
            /health/ready; removes the drop-in and restarts again on failure
  rollback  remove the drop-in and restart; dns-runtime.env is retained
"""
import argparse
import base64
import fcntl
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.request

CONTROL = Path('/etc/cdnca-control')
ENV_FILE = CONTROL / 'dns-runtime.env'
SOURCES = tuple(CONTROL / name for name in ('control.env', 'runtime-extra.env', 'certificate-runtime/environment.env'))
DROPIN = Path('/etc/systemd/system/cdnca-control-api.service.d/50-dns-runtime.conf')
LOCK = Path('/run/lock/cdnca-management-release.lock')
UNIT = 'cdnca-control-api.service'
READY = 'http://127.0.0.1:8080/health/ready'
OWNED = ('DNS_RECONCILE_', 'CNAME_ALLOCATION_')
# Must equal install-control.sh write_environment (test_converge_dns_runtime.py).
FIXED = {
    'DNS_RECONCILE_ENABLED': 'true',
    'DNS_RECONCILE_WORKLOAD_MTLS_ENABLED': 'false',
    'DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS': 'cloudflare=1.1.1.1:53,google=8.8.8.8:53,alidns=223.5.5.5:53',
    'DNS_RECONCILE_PROPAGATION_PUBLIC_RESOLVERS': 'cloudflare=1.1.1.1:53,google=8.8.8.8:53,alidns=223.5.5.5:53',
    'DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM': '2',
    'CNAME_ALLOCATION_HMAC_KEY_ID': 'cname-allocation-v1',
}
SECRET = 'CNAME_ALLOCATION_HMAC_KEY'
DROPIN_CONTENT = f'[Service]\nEnvironmentFile={ENV_FILE}\n'.encode()


def parse_env(content):
    if b'\x00' in content or b'\r' in content:
        raise ValueError('invalid environment encoding')
    values = {}
    for line in content.decode().split('\n'):
        if not line or line.startswith('#'):
            continue
        name, separator, value = line.partition('=')
        if not separator or not re.fullmatch(r'[A-Z][A-Z0-9_]*', name) or name in values:
            raise ValueError('invalid environment entry')
        values[name] = value
    return values


def read_owned(path, required=True, forbidden=0o077):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        if required:
            raise
        return None
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) & forbidden):
            raise ValueError(f'unsafe file: {path}')
        return source.read(1 << 20)


def valid_runtime(values):
    """True when values hold exactly the managed settings with a valid key."""
    if {name: value for name, value in values.items() if name.startswith(OWNED)}.keys() != {*FIXED, SECRET}:
        return False
    try:
        key = base64.b64decode(values[SECRET], validate=True)
    except ValueError:
        return False
    return all(values[name] == value for name, value in FIXED.items()) and len(key) == 32 and \
        base64.b64encode(key).decode() == values[SECRET]


def render(secret):
    values = {**FIXED, SECRET: base64.b64encode(secret).decode()}
    return ''.join(f'{name}={values[name]}\n' for name in (*FIXED, SECRET)).encode()


def state(sources=SOURCES, env_file=ENV_FILE, dropin=DROPIN):
    """installer | converged | pending; raises on anything it must not touch."""
    contents = [read_owned(path, required=index == 0) for index, path in enumerate(sources)]
    parsed = [parse_env(content) for content in contents if content is not None]
    if valid_runtime(parsed[0]) and not any(name.startswith(OWNED) for values in parsed[1:] for name in values):
        return 'installer'
    if any(name.startswith(OWNED) for values in parsed for name in values):
        raise ValueError('DNS runtime settings already exist in a control env file; reconcile them manually')
    existing = read_owned(env_file, required=False)
    installed = read_owned(dropin, required=False, forbidden=0o022)
    if existing is not None and not valid_runtime(parse_env(existing)):
        raise ValueError(f'{env_file} has unexpected content; refusing to replace its CNAME key')
    if installed is not None and installed != DROPIN_CONTENT:
        raise ValueError(f'{dropin} has unexpected content')
    return 'converged' if existing is not None and installed is not None else 'pending'


def write_new(path, content, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())
    os.chmod(path, mode)


def locked(lock):
    fd = os.open(lock, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError('unsafe management release lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise ValueError('a management release/upgrade holds the release lock; retry later') from None
    except BaseException:
        os.close(fd)
        raise
    return fd


def probe(url=READY):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status == 200
    except OSError:
        return False


def restart(run, check, wait):
    if run(['systemctl', 'daemon-reload'], capture_output=True, timeout=60, check=False).returncode or \
            run(['systemctl', 'restart', UNIT], capture_output=True, timeout=120, check=False).returncode:
        return False
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(2)
    return False


def apply(sources=SOURCES, env_file=ENV_FILE, dropin=DROPIN, lock=LOCK, run=subprocess.run, check=probe, wait=90.0):
    fd = locked(lock)
    try:
        current = state(sources, env_file, dropin)
        if current != 'pending':
            return f'already enabled ({current})'
        if read_owned(env_file, required=False) is None:
            write_new(env_file, render(secrets.token_bytes(32)), 0o400)
        dropin.parent.mkdir(mode=0o755, exist_ok=True)
        write_new(dropin, DROPIN_CONTENT, 0o644)
        if restart(run, check, wait):
            return f'DNS write runtime enabled; settings in {env_file}'
        dropin.unlink()
        if restart(run, check, wait):
            raise ValueError('control-api failed with the DNS runtime enabled; drop-in removed and service healthy again')
        raise ValueError(f'control-api is NOT healthy after removing the drop-in; inspect {UNIT}')
    finally:
        os.close(fd)


def rollback(env_file=ENV_FILE, dropin=DROPIN, lock=LOCK, run=subprocess.run, check=probe, wait=90.0):
    fd = locked(lock)
    try:
        if read_owned(dropin, required=False, forbidden=0o022) != DROPIN_CONTENT:
            raise ValueError(f'{dropin} is missing or not ours; nothing to roll back')
        dropin.unlink()
        if restart(run, check, wait):
            return f'DNS write runtime disabled; {env_file} retained'
        raise ValueError(f'control-api is not healthy after rollback; inspect {UNIT}')
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('action', choices=('check', 'apply', 'rollback'))
    action = parser.parse_args(argv).action
    try:
        if os.geteuid() != 0:
            raise ValueError('run as root (control env files are root-only)')
        if action == 'check':
            print(f'state: {state()}')
            sys.stdout.writelines(f'{name}={value}\n' for name, value in FIXED.items())
            print(f'{SECRET}=<generated once, 32 random bytes>')
            return 0
        print(apply() if action == 'apply' else rollback())
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

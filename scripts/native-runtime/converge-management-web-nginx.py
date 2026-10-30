#!/usr/bin/env python3
"""Root-operated, one-shot convergence of an installed management Web nginx.conf.

Upgrades never rewrite /etc/cdnca-control/nginx.conf (only fresh installs run
install-control.sh write_nginx_config), and the native upgrade runner is
sandboxed read-only for /etc, so existing hosts need this explicit step to get
the fresh-install gzip / HTTP/2 / hashed-asset cache settings.

  check     print the unified diff; changes nothing
  apply     CAS-convert, `nginx -t`, atomic replace, reload, local probe;
            restores the original file and reloads again on any failure
  rollback  restore the pre-convergence backup written by apply

Only the exact installer edits are made (including the website root fallback,
asset cache rule, /favicon.ico and /robots.txt, the sandboxed /site/t/ of
theme plugin page bundles, the node installer served from the active
release, and the /dashboard console entry without a trailing slash); any other
local drift is refused.
"""
import argparse
import difflib
import fcntl
import hashlib
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import time

CONFIG = Path('/etc/cdnca-control/nginx.conf')
RUNTIME = Path('/var/lib/cdnca-control/nginx-runtime')
LOCK = Path('/run/lock/cdnca-management-release.lock')
NGINX = Path('/usr/sbin/nginx')
UNIT = 'cdnca-control-web.service'
MARKER = '$cdnca_cache_control'
LIMIT = 1 << 20

HTTP_ADDITIONS = '''    gzip on;
    gzip_static on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 1024;
    # API JSON is not compressed: nginx would weaken its ETag and break revision checks.
    gzip_types application/javascript text/javascript text/css image/svg+xml text/plain;

    # One server-level Cache-Control: a location add_header would drop the
    # inherited security headers. Only successful content-hashed Vite assets
    # are immutable; an empty value lets the brand-asset upstream policy pass.
    map "$status:$uri" $cdnca_cache_control {
        default "no-store";
        "~^(?:200|304):/(?:dashboard/)?assets/[^/]+-[-_A-Za-z0-9]{8,}\\.[^/]+$" "public, max-age=31536000, immutable";
        "~^(?:200|304):/v1/brand-assets/(?:favicon|logo|login_ad)$" "";
    }
'''
AUTH_LOCATION = '''        location ^~ /v1/auth/ {
            # Token-bearing credential responses are never compressed (BREACH).
            gzip off;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_pass http://127.0.0.1:8080;
        }
'''
# The control API trusts loopback as its proxy, so nginx must overwrite any
# client-supplied forwarding chain with the TCP peer instead of appending to it.
XFF_APPEND = '            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'
XFF_PEER = '            proxy_set_header X-Forwarded-For $remote_addr;\n'
LISTEN = re.compile(r'(?m)^        listen ((?:\[[0-9A-Fa-f:]+\]:|[0-9.]+:)?([0-9]{1,5})) ssl( http2)?;$')
SITE_ROOT_OLD = '''        location / {
            try_files $uri $uri/ /index.html;
        }
'''
SITE_ROOT = '''        # The public website (apps/control-site, static/web/site) answers every
        # path outside the console; a release without it keeps the console entry.
        location / {
            try_files $uri /site/index.html /index.html;
        }
'''
SITE_CACHE = '        "~^(?:200|304):/site/assets/[^/]+-[-_A-Za-z0-9]{8,}\\.[^/]+$" "public, max-age=31536000, immutable";\n'
SITE_FILES = '''        location = /favicon.ico { access_log off; log_not_found off; try_files /site/favicon.ico =404; }
        location = /robots.txt { try_files /site/robots.txt =404; }
'''
SITE_FILES_ANCHOR = '        location = /downloads/gateway-ca.pem {\n'
# Theme plugin page bundles (site-theme C): /site/t/ serves the installed
# bundles (${DATA_DIR}/site-themes) under the sandbox CSP and a credential-less
# Access-Control-Allow-Origin: *; the built-in website (/site/index.html,
# /site/assets/) is unchanged and unsandboxed; location / falls back to the
# active bundle's entry (site-themes/current.html) when there is one.
SITE_THEME_ROOT = '''        # Theme plugin page bundles (/site/t/<theme-id>/<version>/, installed by
        # control-api): sandboxed without allow-same-origin, in an opaque origin
        # that cannot read the console's cookies or storage. Only here: the
        # built-in website (/site/index.html, /site/assets/) is not sandboxed.
        # Headers set here replace the server's, so those are repeated.
        # A raw /site/t/ request with a dot segment (../, %2e%2e, dot files,
        # also behind an encoded slash) is refused before nginx normalizes it
        # into a path outside the bundles.
        if ($request_uri ~ "^/site/t/(?:[^?]*(?:/|%2[fF]))?(?:\\.|%2[eE])") { return 404; }
        location ^~ /site/t/ {
            alias /var/lib/cdnca-control/site-themes/;
            limit_except GET { deny all; }
            add_header Cache-Control $cdnca_cache_control always;
            add_header X-Content-Type-Options "nosniff" always;
            add_header X-Frame-Options "DENY" always;
            add_header Referrer-Policy "strict-origin-when-cross-origin" always;
            add_header Content-Security-Policy "sandbox allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation; default-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'" always;
            # Module scripts, fonts and fetches of the opaque origin are CORS
            # requests (Origin: null); never with credentials.
            add_header Access-Control-Allow-Origin "*" always;
            error_page 403 404 405 500 502 503 504 /site/t/.error;
            # Bundle paths never start a segment with a dot: those are
            # control-api's staging directories and link swaps.
            location ~ ^/site/t/(?:.*/)?\\. { return 404; }
            location = /site/t/.error {
                internal;
                default_type text/plain;
                return 200 "error\\n";
            }
        }
        # The website answers every path outside the console.
        location / {
            try_files $uri @website;
        }
        # The active page bundle's entry (control-api links site-themes/current.html
        # to it; an internal redirect into /site/t/, under its CSP), else the
        # release's built-in website, else the console entry.
        location @website {
            if (-f /var/lib/cdnca-control/site-themes/current.html) { rewrite ^ /site/t/current.html last; }
            try_files /site/index.html /index.html;
        }
'''
# The node installer follows the active release (64771331e), so a management
# upgrade refreshes it; releases without it fall back to the published copy.
NODE_INSTALLER = '''        # Served from the active release so a management upgrade refreshes the
        # node installer; releases that predate it fall back to the copy
        # published at install time.
        location = /downloads/install-node.sh {
            root /data/cdnca-native-root/cdnca/current/static/web;
            default_type text/x-shellscript;
            try_files $uri @published_node_installer;
        }
        location @published_node_installer {
            root /var/lib/cdnca-control;
            default_type text/x-shellscript;
            try_files /downloads/install-node.sh =404;
        }
'''
NODE_INSTALLER_ANCHOR = '        location ^~ /downloads/ {\n'
# /dashboard without the trailing slash (bbdf331bf); hosts fixed by hand
# before this step (73, 10-27) may carry the block without the comment.
DASHBOARD_ENTRY = '''        # /dashboard without a trailing slash is the console entry too; otherwise it
        # falls to location / -> @website and serves the public website shell.
        location = /dashboard {
            rewrite ^ /index.html break;
        }
'''
DASHBOARD_ENTRY_BLOCK = re.compile(r'(?m)^[ \t]*location[ \t]+=[ \t]*/dashboard[ \t]*\{[ \t]*\n'
                                   r'[ \t]*rewrite[ \t]+\^[ \t]+/index\.html[ \t]+break;[ \t]*\n[ \t]*\}[ \t]*\n')
DASHBOARD_ANCHOR = '        location /dashboard/ {\n'
EDITS = (  # (exact anchor line, replacement), each anchor must occur exactly once
    ('    keepalive_timeout 65;\n', '    keepalive_timeout 65;\n' + HTTP_ADDITIONS),
    ('        add_header Cache-Control "no-store" always;\n', '        add_header Cache-Control $cdnca_cache_control always;\n'),
    ('        location ^~ /v1/ {\n', AUTH_LOCATION + '        location ^~ /v1/ {\n'),
)


def converge(raw):
    """Return (converged bytes, listen port). Raises ValueError for unknown input."""
    if type(raw) is not bytes or not 1 <= len(raw) <= LIMIT or b'\r' in raw or b'\0' in raw:
        raise ValueError('unknown management nginx configuration')
    text = raw.decode('utf-8')
    if text.count('\nhttp {\n') != 1 or 'root /data/cdnca-native-root/cdnca/current/static/web;' not in text:
        raise ValueError('not an installer-generated management nginx configuration')
    listens = LISTEN.findall(text)
    if len(listens) != 1 or not 1 <= int(listens[0][1]) <= 65535:
        raise ValueError('expected exactly one public TLS listener')
    port = int(listens[0][1])
    if MARKER in text:
        before = text.replace(SITE_CACHE, '', 1) if SITE_CACHE in text else text
        expected = (listens[0][2] == ' http2', HTTP_ADDITIONS in before, AUTH_LOCATION in text,
                    '        add_header Cache-Control $cdnca_cache_control always;\n' in text,
                    all(line == XFF_PEER for line in re.findall(r'(?m)^.*X-Forwarded-For.*\n', text)))
        if not all(expected):
            raise ValueError('partially converged configuration; refusing to guess')
        converged = converge_dashboard(converge_node_installer(converge_site(text))).encode('utf-8')
        return (raw if converged == raw else converged), port
    if re.search(r'\bgzip|\bhttp2\b|location \^~ /v1/auth/', text):
        raise ValueError('local gzip/http2/auth customisation present; converge manually')
    for anchor, replacement in EDITS:
        if text.count(anchor) != 1:
            raise ValueError(f'anchor not found exactly once: {anchor.strip()}')
        text = text.replace(anchor, replacement)
    text = text.replace(XFF_APPEND, XFF_PEER)
    forwarded = re.findall(r'(?m)^.*X-Forwarded-For.*\n', text)
    if not forwarded or any(line != XFF_PEER for line in forwarded):
        raise ValueError('unexpected X-Forwarded-For configuration; converge manually')
    text = LISTEN.sub(lambda match: f'        listen {match[1]} ssl http2;', text, count=1)
    return converge_dashboard(converge_node_installer(converge_site(text))).encode('utf-8'), port


def converge_site(text):
    """Adds the public website's root fallback and asset cache rule,
    then its root favicon.ico and robots.txt, then the page bundle sandbox."""
    if SITE_THEME_ROOT in text:
        if not (text.count(SITE_THEME_ROOT) == 1 and text.count(SITE_CACHE) == 1 and text.count(SITE_FILES) == 1):
            raise ValueError('partially converged website sandbox; converge manually')
        return text
    if not (SITE_ROOT in text and SITE_CACHE in text):
        if SITE_ROOT in text or SITE_CACHE in text or text.count(SITE_ROOT_OLD) != 1:
            raise ValueError('unexpected root location; converge manually')
        immutable = '        "~^(?:200|304):/(?:dashboard/)?assets/'
        lines = [line for line in text.splitlines(keepends=True) if line.startswith(immutable)]
        if len(lines) != 1:
            raise ValueError('unexpected asset cache rules; converge manually')
        text = text.replace(SITE_ROOT_OLD, SITE_ROOT).replace(lines[0], lines[0] + SITE_CACHE)
    return converge_site_files(text)


def converge_site_files(text):
    """Serves /favicon.ico and /robots.txt from the website bundle (static/web/site)."""
    if SITE_FILES not in text:
        if re.search(r'(?m)^\s*location = /(?:favicon\.ico|robots\.txt)\b', text) or text.count(SITE_FILES_ANCHOR) != 1:
            raise ValueError('unexpected favicon/robots locations; converge manually')
        text = text.replace(SITE_FILES_ANCHOR, SITE_FILES + SITE_FILES_ANCHOR)
    return converge_site_theme(text)


def converge_site_theme(text):
    """Serves the theme plugin page bundles at /site/t/ under the sandbox CSP,
    and falls back from / to the active bundle's entry when there is one."""
    if (re.search(r'Content-Security-Policy|Access-Control-|site-themes|location \^~ /(?:site|auth)/|location @website', text) or
            text.count(SITE_ROOT) != 1):
        raise ValueError('unexpected website locations or CSP; converge manually')
    return text.replace(SITE_ROOT, SITE_THEME_ROOT)


def converge_node_installer(text):
    """Serves /downloads/install-node.sh from the active release, falling back
    to the copy published at install time."""
    if NODE_INSTALLER in text:
        if text.count(NODE_INSTALLER) != 1 or text.count(NODE_INSTALLER + NODE_INSTALLER_ANCHOR) != 1:
            raise ValueError('partially converged node installer locations; converge manually')
        return text
    if re.search(r'install-node\.sh|@published_node_installer', text) or text.count(NODE_INSTALLER_ANCHOR) != 1:
        raise ValueError('unexpected node installer locations; converge manually')
    return text.replace(NODE_INSTALLER_ANCHOR, NODE_INSTALLER + NODE_INSTALLER_ANCHOR)


def converge_dashboard(text):
    """Serves /dashboard (no trailing slash) as the console entry; a block
    already added by hand (with or without the comment) is converged as is."""
    entries = re.findall(r'(?m)^\s*location\s*=\s*/dashboard\s*\{', text)
    if entries:
        if len(entries) != 1 or len(DASHBOARD_ENTRY_BLOCK.findall(text)) != 1:
            raise ValueError('unexpected /dashboard location; converge manually')
        return text
    if text.count(DASHBOARD_ANCHOR) != 1:
        raise ValueError('unexpected /dashboard/ location; converge manually')
    return text.replace(DASHBOARD_ANCHOR, DASHBOARD_ENTRY + DASHBOARD_ANCHOR)


def read_owned(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or
                info.st_mode & 0o022 or info.st_size > LIMIT):
            raise ValueError(f'unsafe file owner/mode/links: {path}')
        data = b''
        while chunk := os.read(fd, LIMIT + 1 - len(data)):
            data += chunk
        return data, info
    finally:
        os.close(fd)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_dir(path.parent)


def replace(config, data, mode, run, nginx, runtime, expected):
    """Validate `data` with nginx -t, then atomically replace config if it still equals `expected`."""
    staged = config.with_name(f'.{config.name}.converge-{os.getpid()}')
    write_new(staged, data, mode)
    try:
        result = run([str(nginx), '-t', '-q', '-c', str(staged), '-p', str(runtime)],
                     capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0:
            raise ValueError('nginx -t rejected the configuration; nothing changed:\n' + result.stderr.strip())
        if read_owned(config)[0] != expected:
            raise ValueError('configuration changed during preflight; nothing changed')
        os.replace(staged, config)
        sync_dir(config.parent)
    finally:
        if os.path.lexists(staged):
            os.unlink(staged)


def probe(port, h2, timeout=3.0):
    """Loopback self-check: h2 => ALPN negotiates h2; otherwise GET /healthz returns 200 ok."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # loopback readiness only; no credentials are sent
    context.set_alpn_protocols(['h2', 'http/1.1'] if h2 else ['http/1.1'])
    with socket.create_connection(('127.0.0.1', port), timeout=timeout) as raw, \
            context.wrap_socket(raw, server_hostname='localhost') as tls:
        if h2:
            return tls.selected_alpn_protocol() == 'h2'
        tls.sendall(b'GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
        response = b''
        while len(response) <= 65536 and (chunk := tls.recv(4096)):
            response += chunk
    head, _, body = response.partition(b'\r\n\r\n')
    return head.startswith(b'HTTP/1.1 200 ') and body == b'ok\n'


def ready(check, port, converged, wait, sleep=time.sleep):
    deadline = time.monotonic() + wait
    while True:
        try:
            if check(port, False) and (not converged or check(port, True)):
                return True
        except OSError:
            pass
        if time.monotonic() >= deadline:
            return False
        sleep(0.5)


def reload(run, unit):
    return run(['systemctl', 'reload', unit], capture_output=True, timeout=60, check=False).returncode == 0


def locked(lock):
    fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
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


def backup_path(config, original):
    return config.with_name(f'{config.name}.pre-converge-{hashlib.sha256(original).hexdigest()[:16]}')


def apply(config=CONFIG, runtime=RUNTIME, lock=LOCK, nginx=NGINX, unit=UNIT, run=subprocess.run, check=probe, wait=20.0):
    fd = locked(lock)
    try:
        original, info = read_owned(config)
        updated, port = converge(original)
        if updated == original:
            return 'already converged'
        mode = stat.S_IMODE(info.st_mode)
        backup = backup_path(config, original)
        if not os.path.lexists(backup):
            write_new(backup, original, 0o600)
        elif read_owned(backup)[0] != original:
            raise ValueError(f'existing backup differs: {backup}')
        replace(config, updated, mode, run, nginx, runtime, original)
        if reload(run, unit) and ready(check, port, True, wait):
            return f'converged; backup {backup}'
        replace(config, original, mode, run, nginx, runtime, updated)
        if reload(run, unit) and ready(check, port, False, wait):
            raise ValueError('converged nginx failed the reload/probe; original configuration restored and healthy')
        raise ValueError(f'converged nginx failed and the restored original is NOT healthy; inspect {unit}')
    finally:
        os.close(fd)


def rollback(config=CONFIG, runtime=RUNTIME, lock=LOCK, nginx=NGINX, unit=UNIT, run=subprocess.run, check=probe, wait=20.0):
    fd = locked(lock)
    try:
        current, info = read_owned(config)
        _, port = converge(current)
        candidates = sorted(config.parent.glob(f'{config.name}.pre-converge-*'))
        originals = [data for data in (read_owned(path)[0] for path in candidates) if converge(data)[0] == current and data != current]
        if len(originals) != 1:
            raise ValueError('no unique backup whose convergence equals the current configuration')
        replace(config, originals[0], stat.S_IMODE(info.st_mode), run, nginx, runtime, current)
        if reload(run, unit) and ready(check, port, False, wait):
            return 'original configuration restored'
        raise ValueError(f'restored configuration is not healthy; inspect {unit}')
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('action', choices=('check', 'apply', 'rollback'))
    action = parser.parse_args(argv).action
    try:
        if action == 'check':
            original, _ = read_owned(CONFIG)
            updated, _ = converge(original)
            sys.stdout.writelines(difflib.unified_diff(original.decode().splitlines(True), updated.decode().splitlines(True),
                                                       str(CONFIG), str(CONFIG) + ' (converged)'))
            print('already converged' if updated == original else 'convergence pending; run apply', file=sys.stderr)
            return 0
        if os.geteuid() != 0:
            raise ValueError('apply/rollback must run as root')
        print(apply() if action == 'apply' else rollback())
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

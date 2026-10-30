"""Management Web nginx convergence tests; no production services or files."""
from contextlib import redirect_stderr, redirect_stdout
import fcntl
import importlib.util
import io
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('converge_nginx', HERE / 'converge-management-web-nginx.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
# Rendered by write_nginx_config at base 631c658a with the installer's production paths and MASTER_PORT=443.
LEGACY = (HERE / 'testdata/management-web-nginx-631c658a.conf').read_bytes()
INSTALLER = (HERE.parent / 'install-control.sh').read_text()


def render_current(port='443'):
    writer = re.search(r'(?ms)^write_nginx_config\(\) \{.*?^\}\n\n(?=setup_web\(\))', INSTALLER)[0]
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / 'nginx.conf'
        subprocess.run(['bash', '-c', 'set -Eeuo pipefail; mkdir() { :; }; chmod() { :; }; nginx() { :; }\n' + writer +
                        '\nwrite_nginx_config'], check=True, timeout=30, env={**os.environ,
                        'NGINX_CONF': str(target), 'NGINX_RUNTIME_DIR': '/var/lib/cdnca-control/nginx-runtime', 'MASTER_PORT': port,
                        'WEB_ROOT': '/data/cdnca-native-root/cdnca/current/static/web', 'NATIVE_ROOT': '/data/cdnca-native-root/cdnca', 'DATA_DIR': '/var/lib/cdnca-control',
                        'DOWNLOAD_DIR': '/var/lib/cdnca-control/downloads',
                        'PUBLIC_CERT_PATH': '/etc/cdnca-control/keys/pki/public-cert.pem',
                        'PUBLIC_KEY_PATH': '/etc/cdnca-control/keys/pki/public-key.pem'})
        return target.read_bytes()


class ConvergeTests(unittest.TestCase):
    def test_legacy_install_converges_byte_for_byte_to_the_current_fresh_install(self):
        converged, port = C.converge(LEGACY)
        self.assertEqual(port, 443)
        self.assertEqual(converged, render_current())
        self.assertEqual(C.converge(converged), (converged, 443))

    def before_theme_sandbox(self, converged):
        """The configuration a host had before the page bundle sandbox."""
        self.assertEqual(converged.count(C.SITE_THEME_ROOT.encode()), 1)
        return converged.replace(C.SITE_THEME_ROOT.encode(), C.SITE_ROOT.encode())

    def test_public_website_root_and_asset_cache_are_added_once(self):
        converged, _ = C.converge(LEGACY)
        self.assertIn(C.SITE_THEME_ROOT.encode(), converged)
        self.assertEqual(converged.count(C.SITE_CACHE.encode()), 1)
        self.assertNotIn(C.SITE_ROOT_OLD.encode(), converged)
        # A host converged before the website existed gets the website and sandbox edits.
        pre_sandbox = self.before_theme_sandbox(converged)
        earlier = pre_sandbox.replace(C.SITE_ROOT.encode(), C.SITE_ROOT_OLD.encode()).replace(C.SITE_CACHE.encode(), b'')
        self.assertEqual(C.converge(earlier)[0], converged)
        # The current installer renders both edits.
        current = render_current()
        self.assertIn(C.SITE_THEME_ROOT.encode(), current)
        self.assertIn(C.SITE_CACHE.encode(), current)
        with self.assertRaises(ValueError):
            C.converge(earlier.replace(C.SITE_ROOT_OLD.encode(), b'        location / {\n            root /srv;\n        }\n'))

    def test_website_favicon_and_robots_are_added_once(self):
        favicon = b'        location = /favicon.ico { access_log off; log_not_found off; try_files /site/favicon.ico =404; }\n'
        robots = b'        location = /robots.txt { try_files /site/robots.txt =404; }\n'
        converged, _ = C.converge(LEGACY)
        for line in (favicon, robots):
            self.assertEqual(converged.count(line), 1)
            self.assertIn(line, render_current())
        # Idempotent: converging again changes nothing.
        self.assertEqual(C.converge(converged), (converged, 443))
        # Website subpages fall back to the active bundle entry, else the website index.
        self.assertIn(b'        location / {\n            try_files $uri @website;\n        }\n', converged)
        self.assertIn(b'            try_files /site/index.html /index.html;\n', converged)
        # A host converged with the website but before these two gets exactly them.
        earlier = self.before_theme_sandbox(converged).replace(C.SITE_FILES.encode(), b'')
        self.assertEqual(C.converge(earlier)[0], converged)
        # A local favicon/robots location is drift, not overwritten.
        with self.assertRaises(ValueError):
            C.converge(earlier.replace(C.SITE_FILES_ANCHOR.encode(), b'        location = /robots.txt { return 404; }\n' + C.SITE_FILES_ANCHOR.encode()))

    def test_page_bundle_sandbox_is_added_once_and_matches_the_installer(self):
        converged, _ = C.converge(LEGACY)
        current = render_current()
        self.assertEqual(converged.count(C.SITE_THEME_ROOT.encode()), 1)
        self.assertEqual(current.count(C.SITE_THEME_ROOT.encode()), 1)
        # A host converged before the sandbox (website, favicon, robots) gets exactly the sandbox.
        pre_sandbox = self.before_theme_sandbox(converged)
        self.assertNotIn(b'Content-Security-Policy', pre_sandbox)
        self.assertEqual(C.converge(pre_sandbox), (converged, 443))
        self.assertEqual(C.converge(converged), (converged, 443))
        text = converged.decode()
        # The CSP and ACAO live only in location ^~ /site/t/; no server-level CSP or map.
        self.assertEqual(len(re.findall(r'Content-Security-Policy', text)), 1)
        self.assertNotIn('$cdnca_site_csp', text)
        self.assertNotIn('/auth/', text.replace('/v1/auth/', ''))
        bundles = re.search(r'(?ms)^        location \^~ /site/t/ \{.*?^        \}\n', text)[0]
        self.assertIn('alias /var/lib/cdnca-control/site-themes/;', bundles)
        csp = re.search(r'add_header Content-Security-Policy "([^"]*)" always;', bundles)[1]
        self.assertTrue(csp.startswith('sandbox allow-scripts '))
        self.assertNotIn('allow-same-origin', csp)
        self.assertIn('add_header Access-Control-Allow-Origin "*" always;', bundles)
        self.assertNotIn('Allow-Credentials', text)
        self.assertIn('limit_except GET { deny all; }', bundles)
        self.assertIn('error_page 403 404 405 500 502 503 504 /site/t/.error;', bundles)
        # Raw dot segments (../, %2e%2e, also behind %2f) are refused before nginx normalizes them.
        self.assertIn('        if ($request_uri ~ "^/site/t/(?:[^?]*(?:/|%2[fF]))?(?:\\.|%2[eE])") { return 404; }\n'
                      '        location ^~ /site/t/ {\n', text)
        # The location replaces the server's headers, so it repeats every one of them.
        server = re.findall(r'(?m)^        (add_header .*)$', text)
        self.assertTrue(server)
        for header in server:
            self.assertIn('    ' + header, bundles)
        # The built-in website stays as before: no sandbox, served from the release root.
        self.assertNotIn('location ^~ /site/ ', text)
        self.assertIn(C.SITE_FILES, text)
        # / falls back to the active entry under /site/t/ (its CSP), else the built-in website.
        website = re.search(r'(?ms)^        location @website \{.*?^        \}\n', text)[0]
        self.assertIn('if (-f /var/lib/cdnca-control/site-themes/current.html) { rewrite ^ /site/t/current.html last; }', website)
        self.assertIn('try_files /site/index.html /index.html;', website)

    def test_dashboard_entry_without_slash_is_added_once_before_dashboard_slash(self):
        entry, anchor = C.DASHBOARD_ENTRY.encode(), C.DASHBOARD_ANCHOR.encode()
        self.assertNotIn(b'location = /dashboard {', LEGACY)
        converged, _ = C.converge(LEGACY)
        self.assertEqual(converged.count(entry + anchor), 1)
        self.assertEqual(render_current().count(entry + anchor), 1)
        # A host converged before this step gets exactly the entry.
        earlier = converged.replace(entry, b'')
        self.assertNotIn(b'location = /dashboard {', earlier)
        self.assertEqual(C.converge(earlier), (converged, 443))

    def test_dashboard_entry_added_by_hand_is_already_converged(self):
        converged, _ = C.converge(LEGACY)
        entry = C.DASHBOARD_ENTRY.encode()
        block = b'        location = /dashboard {\n            rewrite ^ /index.html break;\n        }\n'
        # 73 (10-27): the block added by hand (with or without the comment, before
        # /dashboard/ or elsewhere) is converged byte for byte: no drift, no refusal.
        for index, by_hand in enumerate((converged, converged.replace(entry, block),
                                         converged.replace(entry, b'').replace(b'        location ~* ^/(?:dashboard/)?', block + b'        location ~* ^/(?:dashboard/)?', 1))):
            with self.subTest(by_hand=index):
                self.assertEqual(C.converge(by_hand), (by_hand, 443))
        # A legacy host with the hand-added block gets every other edit and keeps that block as is.
        legacy = LEGACY.replace(C.DASHBOARD_ANCHOR.encode(), block + C.DASHBOARD_ANCHOR.encode())
        self.assertEqual(C.converge(legacy)[0], converged.replace(entry, block))
        # Anything else at /dashboard is drift, not overwritten.
        for bad in (converged.replace(entry, entry + block),
                    converged.replace(entry, b'        location = /dashboard {\n            return 302 /dashboard/;\n        }\n'),
                    converged.replace(entry, b'').replace(C.DASHBOARD_ANCHOR.encode(), b'        location ^~ /dashboard/ {\n')):
            with self.subTest(bad=bad[:0]), self.assertRaisesRegex(ValueError, 'converge manually'):
                C.converge(bad)

    def test_check_prints_the_dashboard_entry_diff_and_changes_nothing(self):
        converged, _ = C.converge(LEGACY)
        earlier = converged.replace(C.DASHBOARD_ENTRY.encode(), b'')
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'nginx.conf'
            for data, diff, status in ((earlier, True, 'convergence pending; run apply'), (converged, False, 'already converged')):
                config.write_bytes(data)
                config.chmod(0o600)
                out, err = io.StringIO(), io.StringIO()
                with mock.patch.object(C, 'CONFIG', config), redirect_stdout(out), redirect_stderr(err):
                    self.assertEqual(C.main(['check']), 0)
                self.assertEqual(config.read_bytes(), data)
                self.assertEqual(err.getvalue(), status + '\n')
                lines = out.getvalue().splitlines()
                self.assertEqual([line for line in lines if line.startswith('-') and not line.startswith('---')], [])
                # difflib may align the inserted block on either closing brace.
                added = sorted(line for line in lines if line.startswith('+') and not line.startswith('+++'))
                self.assertEqual(added, sorted('+' + line for line in C.DASHBOARD_ENTRY.splitlines()) if diff else [])

    def test_partial_or_local_theme_sandbox_is_refused(self):
        converged, _ = C.converge(LEGACY)
        pre_sandbox = self.before_theme_sandbox(converged)
        for bad in (converged.replace(C.SITE_FILES.encode(), b''),
                    converged + converged[-200:].replace(b'}', b'') + C.SITE_THEME_ROOT.encode(),
                    pre_sandbox.replace(C.SITE_ROOT.encode(), C.SITE_ROOT.encode() + b'        location ^~ /site/t/ { root /srv; }\n'),
                    pre_sandbox.replace(C.SITE_ROOT.encode(), C.SITE_ROOT.encode() + b'        location ^~ /auth/ { root /srv; }\n'),
                    pre_sandbox.replace(b'        add_header X-Frame-Options "DENY" always;\n',
                                 b'        add_header X-Frame-Options "DENY" always;\n        add_header Content-Security-Policy "default-src *" always;\n')):
            with self.subTest(bad=bad[-60:]), self.assertRaises(ValueError):
                C.converge(bad)

    def test_other_ports_and_pre_internal_deny_installs_converge(self):
        for legacy, port in ((LEGACY.replace(b'listen 443 ssl;', b'listen 8443 ssl;'), 8443),
                             (LEGACY.replace(b'listen 443 ssl;', b'listen [::]:9443 ssl;'), 9443)):
            converged, actual = C.converge(legacy)
            self.assertEqual(actual, port)
            self.assertIn(f'ssl http2;'.encode(), converged)
        older = re.sub(rb'        location = /v1/internal \{ return 404; \}\n        location \^~ /v1/internal/ \{ return 404; \}\n', b'',
                       LEGACY.replace(b'    large_client_header_buffers 4 16k;\n', b''))
        self.assertNotEqual(older, LEGACY)
        converged, _ = C.converge(older)
        self.assertIn(C.AUTH_LOCATION.encode() + b'        location ^~ /v1/ {\n', converged)

    def test_unknown_drift_is_refused(self):
        converged, _ = C.converge(LEGACY)
        for bad in (LEGACY.replace(b'\n', b'\r\n'), LEGACY + b'\0', b'',
                    LEGACY.replace(b'    sendfile on;\n', b'    sendfile on;\n    gzip on;\n'),
                    LEGACY.replace(b'keepalive_timeout 65;', b'keepalive_timeout 30;'),
                    LEGACY.replace(b'add_header Cache-Control "no-store" always;', b'add_header Cache-Control "no-cache" always;'),
                    LEGACY.replace(b'        location ^~ /v1/ {', b'        location /v1/ {'),
                    LEGACY.replace(b'listen 443 ssl;', b'listen 443 ssl;\n        listen 8443 ssl;'),
                    LEGACY.replace(b'root /data/cdnca-native-root/cdnca/current/static/web;', b'root /srv/web;'),
                    converged.replace(b'        location ^~ /v1/auth/ {', b'        location ^~ /v1/authx/ {'),
                    converged.replace(b'ssl http2;', b'ssl;'),
                    # converged by the earlier tool revision: client XFF still appended
                    converged.replace(b'X-Forwarded-For $remote_addr;', b'X-Forwarded-For $proxy_add_x_forwarded_for;', 1),
                    LEGACY.replace(b'X-Forwarded-For $proxy_add_x_forwarded_for;', b'X-Forwarded-For $http_x_forwarded_for;', 1)):
            with self.subTest(bad=bad[-80:]), self.assertRaises(ValueError):
                C.converge(bad)


class ApplyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.config, self.lock = self.root / 'nginx.conf', self.root / 'release.lock'
        self.config.write_bytes(LEGACY)
        self.config.chmod(0o600)
        self.lock.write_bytes(b'')
        self.calls, self.nginx_ok, self.healthy = [], True, lambda port, h2: True

    def run_command(self, argv, **_):
        self.calls.append(argv[:2] if argv[0] == 'systemctl' else [argv[1], Path(argv[4]).read_bytes()])
        ok = self.nginx_ok if argv[1] == '-t' else True
        return subprocess.CompletedProcess(argv, 0 if ok else 1, '', '' if ok else 'emerg: fixture')

    def call(self, function):
        return function(config=self.config, runtime=self.root, lock=self.lock, nginx=Path('/fixture/nginx'),
                        run=self.run_command, check=lambda port, h2: self.healthy(port, h2), wait=0)

    def backups(self):
        return sorted(self.root.glob('nginx.conf.pre-converge-*'))

    def test_apply_validates_staged_bytes_backs_up_replaces_and_reloads(self):
        converged, _ = C.converge(LEGACY)
        self.assertIn('backup', self.call(C.apply))
        self.assertEqual(self.config.read_bytes(), converged)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual([path.read_bytes() for path in self.backups()], [LEGACY])
        self.assertEqual(self.calls, [['-t', converged], ['systemctl', 'reload']])
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), sorted(['nginx.conf', 'release.lock', self.backups()[0].name]))
        self.calls.clear()
        self.assertEqual(self.call(C.apply), 'already converged')
        self.assertEqual(self.calls, [])

    def test_nginx_syntax_failure_changes_nothing(self):
        self.nginx_ok = False
        with self.assertRaisesRegex(ValueError, 'nothing changed'):
            self.call(C.apply)
        self.assertEqual(self.config.read_bytes(), LEGACY)
        self.assertEqual([call[0] for call in self.calls], ['-t'])

    def test_concurrent_edit_during_preflight_is_not_overwritten(self):
        edited = LEGACY + b'# operator edit\n'
        run = self.run_command

        def racing(argv, **options):
            if argv[1] == '-t':
                self.config.write_bytes(edited)
            return run(argv, **options)
        self.run_command = racing
        with self.assertRaisesRegex(ValueError, 'changed during preflight'):
            self.call(C.apply)
        self.assertEqual(self.config.read_bytes(), edited)
        self.assertNotIn(['systemctl', 'reload'], self.calls)

    def test_failed_probe_restores_the_original_and_reloads_again(self):
        self.healthy = lambda port, h2: not h2  # old workers answer, HTTP/2 never comes up
        with self.assertRaisesRegex(ValueError, 'original configuration restored and healthy'):
            self.call(C.apply)
        self.assertEqual(self.config.read_bytes(), LEGACY)
        self.assertEqual([call[0] for call in self.calls], ['-t', 'systemctl', '-t', 'systemctl'])
        self.healthy = lambda port, h2: False
        with self.assertRaisesRegex(ValueError, 'NOT healthy'):
            self.call(C.apply)
        self.assertEqual(self.config.read_bytes(), LEGACY)

    def test_held_release_lock_refuses_before_reading(self):
        with self.lock.open('rb') as held:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX)
            with self.assertRaisesRegex(ValueError, 'release lock'):
                self.call(C.apply)
        self.assertEqual(self.calls, [])

    def test_rollback_restores_only_the_matching_backup(self):
        self.call(C.apply)
        self.calls.clear()
        self.assertEqual(self.call(C.rollback), 'original configuration restored')
        self.assertEqual(self.config.read_bytes(), LEGACY)
        self.assertEqual(self.calls, [['-t', LEGACY], ['systemctl', 'reload']])
        with self.assertRaisesRegex(ValueError, 'no unique backup'):
            self.call(C.rollback)


class ProbeTests(unittest.TestCase):
    def test_probe_distinguishes_http2_alpn_and_health_body(self):
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
                            '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True, timeout=60)
            for protocols, h2 in ((['h2', 'http/1.1'], True), (['http/1.1'], False)):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
                context.set_alpn_protocols(protocols)
                listener = socket.create_server(('127.0.0.1', 0))
                port = listener.getsockname()[1]

                def serve():
                    for _ in range(2):
                        connection, _ = listener.accept()
                        try:
                            with context.wrap_socket(connection, server_side=True) as tls:
                                if tls.selected_alpn_protocol() != 'h2' and tls.recv(4096).startswith(b'GET /healthz '):
                                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n')
                        except (OSError, ssl.SSLError):
                            pass
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                with self.subTest(protocols=protocols):
                    self.assertIs(C.probe(port, True), h2)
                    self.assertTrue(C.probe(port, False))
                thread.join(10)
                listener.close()


if __name__ == '__main__':
    unittest.main()

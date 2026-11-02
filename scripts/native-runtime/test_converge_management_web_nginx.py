"""Management Web nginx convergence tests; no production services or files."""
from contextlib import redirect_stderr, redirect_stdout
import difflib
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


def render_current(port='443', brotli=False, gateway=None):
    writer = re.search(r'(?ms)^write_nginx_config\(\) \{.*?^\}\n\n(?=setup_web\(\))', INSTALLER)[0]
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / 'nginx.conf'
        # The module path the installer checks is pinned; whether it exists is the fixture's choice.
        available = 'true' if brotli else 'false'
        # The writer block runs up to setup_web, so the stub follows it.
        subprocess.run(['bash', '-c', 'set -Eeuo pipefail; mkdir() { :; }; chmod() { :; }; nginx() { :; }\n' + writer +
                        f'\ncontrol_brotli_static_available() {{ {available}; }}\nNGINX_BROTLI_STATIC_MODULE={C.BROTLI_MODULE}\n' +
                        'write_nginx_config'], check=True, timeout=30, env={**os.environ,
                        'NGINX_CONF': str(target), 'NGINX_RUNTIME_DIR': '/var/lib/cdnca-control/nginx-runtime', 'MASTER_PORT': port,
                        'WEB_ROOT': '/data/cdnca-native-root/cdnca/current/static/web', 'NATIVE_ROOT': '/data/cdnca-native-root/cdnca', 'DATA_DIR': '/var/lib/cdnca-control',
                        'DOWNLOAD_DIR': '/var/lib/cdnca-control/downloads', 'INSTALL_ENV': '', 'WEB_LISTEN': port, 'WEB_REAL_IP': '',
                        'PUBLIC_CERT_PATH': '/etc/cdnca-control/keys/pki/public-cert.pem',
                        'PUBLIC_KEY_PATH': '/etc/cdnca-control/keys/pki/public-key.pem',
                        **({'GATEWAY_HOST': gateway[0], 'GATEWAY_AGENT_PORT': str(gateway[1])} if gateway else {})})
        return target.read_bytes()


def origin_auth(raw):
    """The installer's own origin_auth_apply_nginx (install-control.sh origin-auth) applied to raw."""
    apply = re.search(r'(?ms)^origin_auth_apply_nginx\(\) \{.*?^\}\n', INSTALLER)[0]
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / 'nginx.conf'
        target.write_bytes(raw)
        subprocess.run(['bash', '-c', 'set -Eeuo pipefail; msg() { printf %s "$1"; }; fail() { echo "$*" >&2; exit 1; }\n'
                        'ORIGIN_AUTH_CONF=/etc/cdnca-control/origin-auth.conf\n' + apply + 'origin_auth_apply_nginx "$1"',
                        'origin-auth', str(target)], check=True, timeout=30, capture_output=True)
        return target.read_bytes()


class OriginAuthTests(unittest.TestCase):
    """Hosts behind a CDN (install-control.sh origin-auth / --origin-auth): 73, 11-02."""

    def test_origin_auth_form_is_the_installer_rewrite(self):
        current = origin_auth(render_current())
        self.assertEqual(current.count(C.PLAN_SOURCE.encode() + C.ORIGIN_AUTH_INCLUDE.encode()), 1)
        self.assertEqual(current.count(C.XFF_CLIENT.encode()), 6)
        self.assertEqual(current.count(C.REAL_IP_CLIENT.encode()), 6)
        self.assertNotIn(b'$remote_addr;', current.replace(b'default $remote_addr;', b''))
        # Re-running origin-auth changes nothing, and the converger's rewrite equals it.
        self.assertEqual(origin_auth(current), current)
        self.assertEqual(C.render_origin_auth(render_current().decode()).encode(), current)

    def test_unconverged_origin_auth_host_converges_to_the_current_installer_with_origin_auth(self):
        current = origin_auth(render_current())
        gateway = ('gateway.example.com', 29407)
        # origin-auth before any convergence (legacy XFF append stays as is), and on a host converged before
        # the /agent/v1/ tunnel and the /v1/ WebSocket upgrade (73's state before 11-02).
        before_tunnel = render_current(gateway=gateway).replace(C.agent_tunnel(gateway).encode(), b'')
        before_tunnel = before_tunnel.replace(C.WS_MAP.encode(), b'').replace(C.WS_HEADERS.encode(), b'')
        for name, earlier, agent, expected in (
                ('legacy', origin_auth(LEGACY), C.DEFAULT_AGENT, current),
                ('before tunnel', origin_auth(before_tunnel), gateway, origin_auth(render_current(gateway=gateway)))):
            with self.subTest(name):
                self.assertNotEqual(earlier, expected)
                self.assertEqual(C.converge(earlier, agent=agent), (expected, 443))
        # The added locations get the client IP too: no $remote_addr proxy header is left.
        self.assertNotIn(C.XFF_PEER.encode(), current)
        self.assertNotIn(C.REAL_IP_PEER.encode(), current)

    def test_converged_origin_auth_host_is_unchanged(self):
        for brotli in (False, True):
            current = origin_auth(render_current(brotli=brotli))
            with self.subTest(brotli=brotli):
                self.assertEqual(C.converge(current, brotli=brotli), (current, 443))
        # With a bound domain the copy carries the same rewrite.
        current = render_current().decode()
        bound = C.render_bind(C.split_bind(current)[0], ('console.example.com', '/etc/b-cert.pem', '/etc/b-key.pem'))
        bound = origin_auth(bound.encode())
        self.assertEqual(bound.count(C.XFF_CLIENT.encode()), 12)
        self.assertEqual(C.converge(bound), (bound, 443))

    def test_hand_edits_in_the_origin_auth_form_are_refused(self):
        current = origin_auth(render_current())
        include, key = C.ORIGIN_AUTH_INCLUDE.encode(), b'            proxy_set_header X-Cdnca-Origin-Key "";\n'
        for name, bad in (
                ('client XFF without the key line', current.replace(key, b'', 1)),
                ('key header with a value', current.replace(key, key.replace(b'""', b'"x"'), 1)),
                ('extra client IP header', current.replace(C.REAL_IP_CLIENT.encode(), C.REAL_IP_CLIENT.encode() +
                                                           b'            proxy_set_header X-Client $cdnca_client_ip;\n', 1)),
                ('include moved', current.replace(include, b'').replace(b'    server_tokens off;\n', b'    server_tokens off;\n' + include)),
                ('include twice', current.replace(include, include + include)),
                ('client IP without the include', current.replace(include, b'')),
                ('ordinary drift', current.replace(b'ssl http2;', b'ssl;')),
                ('auth location edited', current.replace(b'            # Token-bearing credential responses are never compressed (BREACH).\n'
                                                         b'            gzip off;\n', b'')),
                ('agent tunnel edited', current.replace(b'proxy_buffering off;', b'proxy_buffering on;'))):
            with self.subTest(name), self.assertRaises(ValueError):
                C.converge(bad)
        # A plain host is unaffected: origin-auth lines without the include are drift too.
        with self.assertRaises(ValueError):
            C.converge(render_current().replace(C.XFF_PEER.encode(), C.XFF_CLIENT.encode(), 1))

    def test_73_after_the_hand_added_tunnel_and_websocket_upgrade_checks_as_converged(self):
        # nginx.conf.bak-agentv1-20261102054216: converged before /agent/v1/ and the /v1/ upgrade, then origin-auth.
        gateway = ('gateway.example.com', 29407)
        current = render_current(gateway=gateway)
        tunnel = C.agent_tunnel(gateway).encode()
        backup = origin_auth(current.replace(tunnel, b'').replace(C.WS_MAP.encode(), b'').replace(C.WS_HEADERS.encode(), b''))
        self.assertEqual(backup.count(b'X-Forwarded-For $cdnca_client_ip;'), 5)
        # The orchestrator then added the installer's /agent/v1/ block and the /v1/ map plus Upgrade/Connection lines.
        anchor = (C.BILLING_BRIDGE + C.NODE_INSTALLER_ANCHOR).encode()
        by_hand = (backup.replace(anchor, C.BILLING_BRIDGE.encode() + tunnel + C.NODE_INSTALLER_ANCHOR.encode())
                   .replace(C.WS_MAP_ANCHOR.encode(), (C.WS_MAP_ANCHOR + C.WS_MAP).encode())
                   .replace(C.API_GZIP.encode(), (C.API_GZIP + C.WS_HEADERS).encode()))
        expected = origin_auth(current)
        # The pasted block keeps the template's $remote_addr: the only pending change is giving it the client IP.
        converged, _ = C.converge(by_hand, agent=gateway)
        self.assertEqual(converged, expected)
        diff = [line for line in difflib.unified_diff(by_hand.decode().splitlines(), converged.decode().splitlines(), lineterm='', n=0)
                if line[:1] in '+-' and line[:3] not in ('+++', '---')]
        self.assertEqual(diff, ['-' + C.REAL_IP_PEER.rstrip('\n'), '-' + C.XFF_PEER.rstrip('\n')] +
                         ['+' + line for line in (C.REAL_IP_CLIENT + C.XFF_CLIENT).splitlines()])
        # Had the block been pasted with origin-auth's rewrite as well, check reports it converged.
        self.assertEqual(C.converge(origin_auth(by_hand), agent=gateway), (expected, 443))
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'nginx.conf'
            config.write_bytes(expected)
            config.chmod(0o600)
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(C, 'CONFIG', config), mock.patch.object(C, 'gateway_agent', lambda: gateway), \
                    redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(C.main(['check']), 0)
            self.assertEqual((out.getvalue(), err.getvalue()), ('', 'already converged\n'))


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

    def test_bound_domain_block_follows_the_converged_installer_server(self):
        # control-api control-host bind adds a marked copy of the server for the domain.
        def bind(text):
            bound, _ = C.split_bind(text)
            return C.render_bind(bound, ('console.example.com', '/etc/cdnca-control/keys/pki/bind-public-cert.pem',
                                         '/etc/cdnca-control/keys/pki/bind-public-key.pem'))
        current = render_current()
        bound_current = bind(current.decode()).encode()
        self.assertEqual(C.converge(bound_current)[0], bound_current)
        self.assertEqual(bound_current.count(b'server_name console.example.com;'), 1)
        self.assertEqual(bound_current.count(b'listen 443 ssl http2;'), 2)
        legacy_bound = bind(LEGACY.decode()).encode()
        self.assertEqual(C.converge(legacy_bound)[0], bound_current)
        self.assertEqual(C.split_bind(bound_current.decode())[0].encode(), current)
        with self.assertRaises(ValueError):
            C.converge(bound_current.replace(b'server_name console.example.com;', b'server_name a; server_name b;'))

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

    def test_log_read_json_gzip_is_added_once_and_matches_the_installer(self):
        block = C.API_GZIP.encode()
        self.assertNotIn(b'application/json', LEGACY)
        converged, _ = C.converge(LEGACY)
        self.assertEqual(converged.count(block), 1)
        self.assertEqual(converged.count(b'application/json'), 1)
        self.assertEqual(render_current().count(block), 1)
        # A host converged before this step gets exactly the sub-location.
        earlier = converged.replace(block, C.API_GZIP_ANCHOR.encode())
        self.assertEqual(C.converge(earlier), (converged, 443))
        # JSON compression added by hand anywhere else is refused.
        with self.assertRaises(ValueError):
            C.converge(earlier.replace(b'image/svg+xml text/plain;', b'image/svg+xml text/plain application/json;'))

    def test_website_content_json_gzip_upgrades_a_logs_only_host(self):
        converged, _ = C.converge(LEGACY)
        self.assertIn(b'|control-site/content)$ {', converged)
        # A host converged by api-gzip alone (log reads only) gets the content route too.
        logs_only = converged.replace(C.API_GZIP.encode(), C.API_GZIP_LOGS.encode())
        self.assertNotEqual(logs_only, converged)
        self.assertEqual(C.converge(logs_only), (converged, 443))
        # A hand-edited sub-location is drift.
        with self.assertRaises(ValueError):
            C.converge(converged.replace(b'|control-site/content)$ {', b'|control-site/content|sites)$ {'))

    def test_favicon_fallback_and_billing_bridge_downloads_are_added_once(self):
        converged, _ = C.converge(LEGACY)
        current = render_current()
        for block in (C.FAVICON_ERROR, C.FAVICON_FALLBACK + C.FAVICON_FALLBACK_ANCHOR,
                      C.NODE_INSTALLER + C.BILLING_BRIDGE):
            self.assertEqual(converged.count(block.encode()), 1, block)
            self.assertEqual(current.count(block.encode()), 1, block)
        self.assertNotIn(C.FAVICON_ERROR_OLD.encode(), converged)
        # A host converged before these steps gets exactly them.
        earlier = (converged.replace(C.FAVICON_ERROR.encode(), C.FAVICON_ERROR_OLD.encode())
                   .replace(C.FAVICON_FALLBACK.encode(), b'').replace(C.BILLING_BRIDGE.encode(), b'')
                   .replace(C.HTTP_END.encode(), C.HTTP_END_OLD.encode()))
        self.assertEqual(C.converge(earlier), (converged, 443))
        for bad in (converged.replace(C.FAVICON_FALLBACK.encode(), b''),
                    earlier.replace(C.NODE_INSTALLER_ANCHOR.encode(), b'        location ^~ /downloads/billing-bridge/ { root /srv; }\n' +
                                    C.NODE_INSTALLER_ANCHOR.encode()),
                    converged.replace(b'default_type application/zip;', b'default_type text/html;'),
                    converged[:-3] + b'\n}\n# local\n'):
            with self.subTest(bad=bad[-60:]), self.assertRaises(ValueError):
                C.converge(bad)

    def test_node_websocket_tunnel_is_added_once_with_the_gateway_env_values(self):
        # Hosts installed before 547f9e6f1 (73, 11-02) had no /agent/v1/: /agent/v1/enroll answered 200 HTML.
        self.assertNotIn(b'/agent/v1', LEGACY)
        gateway = ('gateway.example.com', 29407)
        converged, _ = C.converge(LEGACY, agent=gateway)
        self.assertEqual(converged, render_current(gateway=gateway))
        tunnel = C.agent_tunnel(gateway).encode()
        self.assertEqual(converged.count(C.BILLING_BRIDGE.encode() + tunnel + C.NODE_INSTALLER_ANCHOR.encode()), 1)
        self.assertIn(b'proxy_ssl_name gateway.example.com;', tunnel)
        self.assertIn(b'proxy_pass https://127.0.0.1:29407;', tunnel)
        # Idempotent; a host that has the block keeps its own values whatever gateway.env says now.
        self.assertEqual(C.converge(converged, agent=gateway), (converged, 443))
        self.assertEqual(C.converge(converged), (converged, 443))
        # A host converged before this step (every other edit present) gets exactly the block.
        earlier = converged.replace(tunnel, b'')
        self.assertEqual(C.converge(earlier, agent=gateway), (converged, 443))
        # Local edits of the block, a second /agent/v1 location or a bad endpoint are refused.
        for bad, agent in ((converged.replace(b'proxy_buffering off;', b'proxy_buffering on;'), gateway),
                           (earlier.replace(C.NODE_INSTALLER_ANCHOR.encode(), b'        location /agent/v1/ { return 404; }\n' +
                                            C.NODE_INSTALLER_ANCHOR.encode()), gateway),
                           (earlier, ('bad host;', 20407)), (earlier, ('gateway.example.com', 0))):
            with self.subTest(agent=agent), self.assertRaises(ValueError):
                C.converge(bad, agent=agent)

    def test_v1_websocket_upgrade_is_added_once(self):
        # wss /v1/nodes/{id}/ssh-terminal needs Upgrade/Connection passed to control-api.
        current = render_current()
        self.assertEqual(current.count((C.WS_MAP_ANCHOR + C.WS_MAP).encode()), 1)
        self.assertEqual(current.count((C.API_GZIP + C.WS_HEADERS).encode()), 1)
        self.assertEqual(C.converge(current), (current, 443))
        earlier = current.replace(C.WS_MAP.encode(), b'').replace(C.WS_HEADERS.encode(), b'')
        self.assertNotIn(b'$connection_upgrade', earlier)
        self.assertEqual(C.converge(earlier), (current, 443))
        with self.assertRaises(ValueError):
            C.converge(current.replace(C.WS_HEADERS.encode(), b''))

    def test_gateway_agent_reads_gateway_env(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / 'gateway.env'
            self.assertEqual(C.gateway_agent(env), C.DEFAULT_AGENT)
            env.write_text('CDNCA_GATEWAY_ENROLLMENT_ADDR=0.0.0.0:29402\nCDNCA_GATEWAY_AGENT_ADDR=0.0.0.0:20407\n'
                           'CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT=gateway.cdnca.com:20407\n')
            env.chmod(0o600)
            self.assertEqual(C.gateway_agent(env), ('gateway.cdnca.com', 20407))
            env.write_text('CDNCA_GATEWAY_AGENT_ADDR=0.0.0.0:20407\nCDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT=[2001:db8::1]:20407\n')
            self.assertEqual(C.gateway_agent(env), ('2001:db8::1', 20407))
            env.write_text('CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT=gateway.cdnca.com:20407\n')
            with self.assertRaises(ValueError):
                C.gateway_agent(env)

    def test_brotli_static_only_where_the_module_is_installed(self):
        plain, _ = C.converge(LEGACY)
        self.assertNotIn(b'brotli', plain)
        brotli, _ = C.converge(LEGACY, brotli=True)
        # Byte for byte the installer's rendering on a host with the module.
        self.assertEqual(brotli, render_current(brotli=True))
        self.assertTrue(brotli.startswith(C.BROTLI_LOAD.encode()))
        self.assertEqual(brotli.count((C.STATIC_ASSETS + C.BROTLI_STATIC).encode()), 1)
        self.assertEqual(brotli.count(b'brotli'), 2)
        # Idempotent; a host converged without the module gets it once installed.
        self.assertEqual(C.converge(brotli, brotli=True), (brotli, 443))
        self.assertEqual(C.converge(plain, brotli=True), (brotli, 443))
        # brotli configured but the module gone (nginx -t would fail), or by hand: refused.
        for bad, available in ((brotli, False), (plain.replace(C.STATIC_ASSETS.encode(), (C.STATIC_ASSETS + C.BROTLI_STATIC).encode()), True),
                               (b'load_module /x.so;\n' + plain, True)):
            with self.subTest(bad=bad[:40]), self.assertRaises(ValueError):
                C.converge(bad, brotli=available)
        # A BaoTa host's own nginx cannot load the distribution module.
        baota = plain.replace(C.HTTP_END.encode(), b'\n    }\n' + C.BAOTA_DOWNLOAD.encode() + b'\n    server { }\n}\n')
        self.assertEqual(C.converge(baota, brotli=True), (baota, 443))

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
                        run=self.run_command, check=lambda port, h2: self.healthy(port, h2), wait=0, brotli=False,
                        agent=C.DEFAULT_AGENT)

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

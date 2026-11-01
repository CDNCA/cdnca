#!/usr/bin/env bash
# Runs inside a container. "old" lays out a native control host the way
# install-control.sh does (same paths, unit names, PostgreSQL roles/database,
# NATS JetStream store, object store data) with stand-in writer services;
# "target" only installs the dependency stand-in the migration runs.
set -Eeuo pipefail
umask 077
role=$1
ip=${2:-}  # old: this host's address; the Gateway is published by IP (migrate-ip)
root=/data/cdnca-native-root/cdnca
release=$root/releases/e2e
pg() { runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 "$@"; }

# Stand-in for install-ubuntu-dependencies.sh: start PostgreSQL (installed in
# the image, empty cluster) and refuse an occupied target like the real one.
dependencies_script() {
  cat <<'EOF'
#!/bin/bash
set -euo pipefail
[ "$1" = install ]
for p in /etc/cdnca-control/control.env /var/lib/cdnca-control; do [ ! -e "$p" ] || { echo "native_dependencies: existing $p" >&2; exit 1; }; done
systemctl enable --now postgresql >/dev/null 2>&1
for _ in $(seq 30); do runuser -u postgres -- psql -Atc 'select 1' >/dev/null 2>&1 && exit 0; sleep 1; done
exit 1
EOF
}

# ClickHouse is not installed in the fixture: report "no analytics database"
# so the clickhouse component records an empty archive on both hosts.
clickhouse_stub() {
  printf '#!/bin/sh\ncase "$*" in *"SELECT version()"*) echo 25.3.6.56;; *EXISTS*) echo 0;; esac\n'
}

# The target stays an empty system: the migration brings everything.
[ "$role" = old ] || exit 0

dependencies_script | install -m 0700 /dev/stdin /tmp/deps.sh
bash /tmp/deps.sh install
clickhouse_stub | install -m 0755 /dev/stdin /usr/bin/clickhouse-client

install -d -m 0700 /etc/cdnca-control /etc/cdnca-control/keys /etc/cdnca-control/keys/pki /var/lib/cdnca-control
install -d -m 0755 "$release/bin" /usr/local/cdnca-control/support /var/lib/cdnca-control/downloads
dependencies_script | install -m 0700 /dev/stdin /usr/local/cdnca-control/support/install-ubuntu-dependencies.sh
install -m 0755 /opt/fixture/control-api "$release/bin/control-api"
ln -sfn releases/e2e "$root/current"
sha=$(sha256sum "$release/bin/control-api" | awk '{print $1}')
printf '{"version":"1.0.35","source":{"commit":"%s"},"files":[{"path":"bin/control-api","sha256":"%s","mode":493}]}\n' \
  "$(printf e2e | sha256sum | cut -c1-40)" "$sha" >"$release/release.manifest.json"
chmod 0644 "$release/release.manifest.json"
password=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
cat >/etc/cdnca-control/control.env <<EOF
DATABASE_URL=postgres://cdnca:${password}@127.0.0.1:5432/cdnca?sslmode=disable
CONTROL_INSTALLATION_ID=6b0d4d4e-8c3a-4d7e-9a35-0f5c2a7b1e01
CONTROL_INSTALLATION_NAME=control-e2e
CONTROL_VERSION=1.0.35
LICENSE_SERVICE_URL=https://license.example.invalid
EOF
cat >>/etc/cdnca-control/control.env <<EOF
CDNCA_GATEWAY_LOCAL_ADDRESS=${ip}:19444
CDNCA_GATEWAY_LOCAL_SERVER_NAME=${ip}
CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS=${ip}:19443
EOF
printf 'CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT=%s:19444\nCDNCA_GATEWAY_ENROLLMENT_ADDR=0.0.0.0:19443\n' "$ip" >/etc/cdnca-control/gateway.env
printf 'node-ca-private-key-material\n' >/etc/cdnca-control/keys/pki/node-ca-key.pem
cat >/var/lib/cdnca-control/runtime-config.js <<EOF
window.__CDNCA_GATEWAY_ADDRESS__ = "${ip}:19444";
window.__CDNCA_GATEWAY_ENROLLMENT_ADDRESS__ = "${ip}:19443";
window.__CDNCA_GATEWAY_SERVER_NAME__ = "${ip}";
EOF
chmod 0600 /etc/cdnca-control/*.env /etc/cdnca-control/keys/pki/node-ca-key.pem

# Installation PKI as install-control.sh lays it out: the root signs the
# Gateway server certificate (SAN = this host's IP) and the node client
# certificates (one URI SAN spiffe://cdn-platform/node/<id>).
pki=/etc/cdnca-control/keys/pki
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj /CN=cdnca-e2e-root \
  -keyout $pki/root-ca-key.pem -out $pki/root-ca-cert.pem 2>/dev/null
issue() { # issue NAME SUBJECT EXTENSIONS
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$2" -keyout "$pki/$1-key.pem" -out "/tmp/$1.csr" 2>/dev/null
  printf '%s\n' "$3" >"/tmp/$1.ext"
  openssl x509 -req -in "/tmp/$1.csr" -CA $pki/root-ca-cert.pem -CAkey $pki/root-ca-key.pem -CAcreateserial -days 825 \
    -extfile "/tmp/$1.ext" -out "$pki/$1.pem" 2>/dev/null
}
issue gateway-server "$ip" "subjectAltName=IP:${ip},DNS:control.e2e.test
extendedKeyUsage=serverAuth
keyUsage=digitalSignature"
chmod 0444 $pki/gateway-server.pem; chmod 0600 $pki/*-key.pem
# Node identities leave with run.sh (they live on the nodes, not the control host).
install -d -m 0700 /opt/fixture/nodes
for node in 11111111-1111-4111-8111-111111111111 22222222-2222-4222-8222-222222222222; do
  issue "node-$node" node "subjectAltName=URI:spiffe://cdn-platform/node/$node
extendedKeyUsage=clientAuth
keyUsage=digitalSignature"
  install -d -m 0700 "/opt/fixture/nodes/$node/tls"
  mv "$pki/node-$node.pem" "/opt/fixture/nodes/$node/tls/client.pem"
  mv "$pki/node-$node-key.pem" "/opt/fixture/nodes/$node/tls/client-key.pem"
  cp $pki/root-ca-cert.pem "/opt/fixture/nodes/$node/tls/ca.pem"
done
rm -f /tmp/*.csr /tmp/*.ext $pki/root-ca-cert.srl
chmod 0644 /var/lib/cdnca-control/runtime-config.js

pg --dbname postgres <<SQL
\\set pw '${password}'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', 'cdnca', :'pw')\\gexec
CREATE ROLE cdnca_control_app NOLOGIN NOINHERIT;
CREATE DATABASE cdnca OWNER cdnca;
\\connect cdnca
ALTER SCHEMA public OWNER TO cdnca;
SET ROLE cdnca;
CREATE TABLE schema_migrations (version bigint PRIMARY KEY);
INSERT INTO schema_migrations SELECT generate_series(1, 302);
CREATE TABLE nodes (id uuid PRIMARY KEY, name text NOT NULL, admin_state text NOT NULL);
CREATE TABLE node_presence (node_id uuid PRIMARY KEY REFERENCES nodes(id), status text NOT NULL, last_seen_at timestamptz);
INSERT INTO nodes VALUES ('11111111-1111-4111-8111-111111111111', 'edge-a', 'active'),
  ('22222222-2222-4222-8222-222222222222', 'edge-b', 'active');
INSERT INTO node_presence SELECT id, 'offline', NULL FROM nodes;
-- migration 448 shape: the Gateway settings page entry points.
CREATE TABLE agent_gateway_entrypoints (
    position integer PRIMARY KEY CHECK (position BETWEEN 1 AND 16),
    address text NOT NULL UNIQUE CHECK (char_length(address) BETWEEN 3 AND 260),
    server_name text NOT NULL CHECK (char_length(server_name) BETWEEN 1 AND 253 AND server_name = lower(server_name)),
    transport text NOT NULL CHECK (transport IN ('grpc', 'ws')),
    tunnel_host text NOT NULL DEFAULT '' CHECK (char_length(tunnel_host) <= 253 AND tunnel_host = lower(tunnel_host)),
    CHECK (transport = 'ws' OR tunnel_host = '')
);
CREATE TABLE sites (id serial PRIMARY KEY, domain text NOT NULL);
INSERT INTO sites (domain) SELECT 'site-' || g || '.example' FROM generate_series(1, 2000) g;
CREATE TABLE writes (id bigserial PRIMARY KEY, writer text NOT NULL, at timestamptz NOT NULL DEFAULT now());
GRANT SELECT ON sites TO cdnca_control_app;
SQL

# NATS JetStream exactly as setup_nats writes it.
install -m 0755 /opt/fixture/nats-server /usr/local/bin/nats-server
install -d -m 0700 /var/lib/cdnca-control/nats
printf '{"host":"127.0.0.1","port":4222,"http":"127.0.0.1:8222","jetstream":{"store_dir":"/var/lib/cdnca-control/nats"}}\n' >/etc/cdnca-control/nats.json
cat >/etc/systemd/system/cdnca-control-nats.service <<'EOF'
[Unit]
Description=CDNCA local NATS JetStream
[Service]
ExecStart=/usr/local/bin/nats-server -c /etc/cdnca-control/nats.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

# Object store data owned by its service account (uid differs on the target).
useradd --system --user-group --uid 990 --no-create-home --home-dir /var/lib/cdnca-objectstore --shell /usr/sbin/nologin cdnca-objectstore
install -d -m 0700 -o cdnca-objectstore -g cdnca-objectstore /var/lib/cdnca-objectstore/cdnca-assets /var/lib/cdnca-objectstore-logs
head -c 1048576 /dev/urandom >/var/lib/cdnca-objectstore/cdnca-assets/brand-logo.bin
chown cdnca-objectstore: /var/lib/cdnca-objectstore/cdnca-assets/brand-logo.bin
cat >/etc/systemd/system/cdnca-objectstore.service <<'EOF'
[Unit]
Description=Object store stand-in
[Service]
User=cdnca-objectstore
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
EOF

# Writer stand-in: control-api keeps writing PostgreSQL every 200 ms and
# serves /health/ready. The Gateway is the production Connect service
# (services/agent-gateway TestMigrateIPGatewayProcess, under the support
# tree so the migration carries it): mTLS with the PKI above, the
# GatewayHello endpoint list from control.env + agent_gateway_entrypoints,
# node_presence updated on connect/disconnect.
cat >/usr/local/cdnca-control/support/writer.py <<'EOF'
import http.server, subprocess, sys, threading, time
kind, port = sys.argv[1], int(sys.argv[2])
def sql(statement):
    subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-X", "-q", "-d", "cdnca", "-c", statement], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def write():
    while True:
        sql(f"INSERT INTO writes (writer) VALUES ('{kind}')")
        time.sleep(0.2)
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *args): pass
threading.Thread(target=write, daemon=True).start()
http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
EOF
chmod 0755 /usr/local/cdnca-control/support/writer.py
cat >/etc/systemd/system/cdnca-control-api.service <<'EOF'
[Unit]
Description=Stand-in for cdnca-control-api
After=postgresql.service cdnca-control-nats.service
[Service]
ExecStart=/usr/bin/python3 /usr/local/cdnca-control/support/writer.py control-api 8080
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
install -m 0755 /opt/fixture/agent-gateway.test /usr/local/cdnca-control/support/agent-gateway.test
cat >/etc/systemd/system/cdnca-agent-gateway.service <<'EOF'
[Unit]
Description=cdnca-agent-gateway (production Connect service, e2e build)
After=postgresql.service
[Service]
Environment=MIGRATE_IP_E2E_CONFIG_DIR=/etc/cdnca-control
ExecStart=/usr/local/cdnca-control/support/agent-gateway.test -test.run ^TestMigrateIPGatewayProcess$ -test.v -test.timeout 0
Restart=on-failure
RestartSec=1
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now cdnca-control-nats cdnca-objectstore cdnca-control-api cdnca-agent-gateway >/dev/null 2>&1
for _ in $(seq 30); do curl -fsS http://127.0.0.1:8222/healthz >/dev/null 2>&1 && break; sleep 1; done
# Publish real JetStream messages through the NATS API (no CLI needed).
python3 - <<'EOF'
import json, socket
s = socket.create_connection(("127.0.0.1", 4222)); s.recv(4096)
def pub(subject, payload, reply=""):
    data = payload.encode()
    head = f"PUB {subject} {reply} {len(data)}" if reply else f"PUB {subject} {len(data)}"
    s.sendall(head.encode() + b"\r\n" + data + b"\r\n")
s.sendall(b'CONNECT {"verbose":false}\r\nSUB _INBOX.e2e 1\r\n')
pub("$JS.API.STREAM.CREATE.AGENT_COMMANDS", json.dumps({"name": "AGENT_COMMANDS", "subjects": ["agent.commands.>"], "storage": "file"}), "_INBOX.e2e")
import time; time.sleep(1)
for i in range(250):
    pub(f"agent.commands.node{i % 5}", json.dumps({"seq": i}))
s.sendall(b"PING\r\n"); time.sleep(1); s.close()
EOF
"$root/current/bin/control-api" native-backup install-units
echo fixture-ready

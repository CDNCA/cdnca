#!/usr/bin/env bash
# ctl-bind-domain 容器实测（在 ubuntu24 systemd 容器内以 root 运行）：
# 造最小主控布局（私有根 CA、按 IP 的网关/公网证书、安装器 nginx.conf、control.env、节点安装信任），
# 网关与 control-api 用占健康检查端口的假服务代替；用证书文件走 control-host bind，核对结果，再测失败回滚与幂等。
# 用法：control-host-bind-container-test.sh <control-api 二进制> <install-control.sh>
set -Eeuo pipefail
BIN=$1 INSTALLER=$2 IP=203.0.113.10 DOMAIN=console.example.test
PKI=/etc/cdnca-control/keys/pki DL=/var/lib/cdnca-control/downloads
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; exit 1; }
mkdir -p $PKI /etc/cdnca-control/keys/upgrade $DL/edge-agent /var/lib/cdnca-control/nginx-runtime /etc/cdnca-upgrade /run/lock /data/cdnca-native-root/cdnca/current/static/web
chmod 0700 $PKI; : >/etc/cdnca-upgrade/plan-source-nginx.conf; echo ok >/data/cdnca-native-root/cdnca/current/static/web/index.html
ip addr add $IP/32 dev lo 2>/dev/null || true
cd $PKI
# 与 install-control.sh generate_ca/issue_certificate 同参数
printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca' '[dn]' 'CN = Common Name' '[ca]' 'subjectKeyIdentifier = hash' 'basicConstraints = critical,CA:TRUE' 'keyUsage = critical,keyCertSign,cRLSign' >/tmp/ca.cnf
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 -batch -config /tmp/ca.cnf -subj '/CN=CDNCA local control root' -keyout root-ca-key.pem -out root-ca-cert.pem 2>/dev/null
issue() { openssl genrsa -out $1-key.pem 2048 2>/dev/null; openssl req -new -key $1-key.pem -subj "/CN=$2" -out /tmp/$1.csr
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$3" >/tmp/$1.ext
  openssl x509 -req -sha256 -days 825 -in /tmp/$1.csr -CA root-ca-cert.pem -CAkey root-ca-key.pem -CAcreateserial -extfile /tmp/$1.ext -out $1.pem 2>/dev/null; rm -f ./*.srl; }
issue gateway-server $IP "IP:$IP,DNS:localhost,IP:127.0.0.1"; issue public-server $IP "IP:$IP,DNS:localhost,IP:127.0.0.1"
chmod 0600 ./*-key.pem; install -m 0644 root-ca-cert.pem $DL/gateway-ca.pem
GW_KEY_BEFORE=$(openssl pkey -in gateway-server-key.pem -pubout | sha256sum)
# 运营者"公网"证书：独立自签 CA 签发（测试中不受系统信任，验证指纹保留逻辑）
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -batch -subj '/CN=op-ca' -addext basicConstraints=critical,CA:TRUE -keyout /tmp/op-ca.key -out /tmp/op-ca.pem 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$DOMAIN" -keyout /tmp/op.key -out /tmp/op.csr 2>/dev/null
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' $DOMAIN >/tmp/op.ext
openssl x509 -req -days 30 -in /tmp/op.csr -CA /tmp/op-ca.pem -CAkey /tmp/op-ca.key -CAcreateserial -extfile /tmp/op.ext -out /tmp/op.crt 2>/dev/null
cat /tmp/op.crt /tmp/op-ca.pem >/tmp/op-chain.pem
# 升级签名密钥（Ed25519 PKCS#8）与制品信任
for role in control edge; do openssl genpkey -algorithm ed25519 -out /etc/cdnca-control/keys/upgrade/$role-execution.pem; chmod 0400 /etc/cdnca-control/keys/upgrade/$role-execution.pem; done
PUB=$(openssl genpkey -algorithm ed25519 | openssl pkey -pubout | awk 'NR>1&&!/END/' )
printf '{"version":1,"keys":[{"key_id":"release","public_key_pem":"-----BEGIN PUBLIC KEY-----\\n%s\\n-----END PUBLIC KEY-----\\n"}]}\n' "$PUB" >$DL/edge-agent/artifacts.json
cat >/etc/cdnca-control/control.env <<ENV
CONTROL_INSTALLATION_ID=00000000-0000-4000-8000-0000000000aa
CONTROL_UPGRADE_CONTROL_SIGNING_KEY_ID=control-execution-v1
CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE=/etc/cdnca-control/keys/upgrade/control-execution.pem
CONTROL_UPGRADE_EDGE_SIGNING_KEY_ID=edge-execution-v1
CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE=/etc/cdnca-control/keys/upgrade/edge-execution.pem
CONTROL_UPGRADE_ARTIFACT_BASE_URL=https://$IP/downloads/edge-agent/upgrades/sha256
CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE=$PKI/root-ca-cert.pem
PAYMENT_CHANNELS_NOTIFY_BASE=https://$IP
CDNCA_GATEWAY_LOCAL_ADDRESS=$IP:19444
CDNCA_GATEWAY_LOCAL_SERVER_NAME=$IP
CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS=$IP:19443
ENV
chmod 0600 /etc/cdnca-control/control.env
TRUST_SHA=$("$BIN" native-backup publish-node-install-trust)
printf 'upgrade_trust_sha256=%s\ngateway_enrollment_address=%s:19443\ngateway_address=%s:19444\ngateway_server_name=%s\n' $TRUST_SHA $IP $IP $IP >$DL/node-install-defaults
CA_SHA=$(sha256sum $DL/gateway-ca.pem | awk '{print $1}')
cat >/var/lib/cdnca-control/runtime-config.js <<JS
window.__CDNCA_GATEWAY_ADDRESS__ = "$IP:19444";
window.__CDNCA_GATEWAY_ENROLLMENT_ADDRESS__ = "$IP:19443";
window.__CDNCA_GATEWAY_SERVER_NAME__ = "$IP";
window.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = "$TRUST_SHA";
window.__CDNCA_CONTROL_CA_SHA256__ = "$CA_SHA";
JS
# 安装器 write_nginx_config 原样渲染 nginx.conf
# 与 test_converge_management_web_nginx.py render_current 同法：取到 setup_web() 之前
writer=$(awk '/^write_nginx_config\(\) \{/{on=1} /^setup_web\(\) \{/{on=0} on' "$INSTALLER")
export NGINX_CONF=/etc/cdnca-control/nginx.conf NGINX_RUNTIME_DIR=/var/lib/cdnca-control/nginx-runtime WEB_ROOT=/data/cdnca-native-root/cdnca/current/static/web \
  NATIVE_ROOT=/data/cdnca-native-root/cdnca DATA_DIR=/var/lib/cdnca-control DOWNLOAD_DIR=$DL INSTALL_ENV='' WEB_LISTEN=443 WEB_REAL_IP='' MASTER_PORT=443 \
  PUBLIC_CERT_PATH=$PKI/public-server.pem PUBLIC_KEY_PATH=$PKI/public-server-key.pem WRITER="$writer"
bash -c 'set -Eeuo pipefail; control_brotli_static_available() { false; }; control_nginx_mime_types() { echo /etc/nginx/mime.types; }; control_nginx_bin() { command -v nginx; }
eval "$WRITER"; write_nginx_config'
nginx -t -q -c /etc/cdnca-control/nginx.conf -p /var/lib/cdnca-control/nginx-runtime || fail 'installer nginx.conf invalid'
# 三个服务：真 nginx 网页；网关与 control-api 用 python 健康检查替身（8082/8080）
cat >/etc/systemd/system/cdnca-control-web.service <<UNIT
[Service]
ExecStart=$(command -v nginx) -c /etc/cdnca-control/nginx.conf -p /var/lib/cdnca-control/nginx-runtime -g 'daemon off;'
ExecReload=$(command -v nginx) -s reload -c /etc/cdnca-control/nginx.conf -p /var/lib/cdnca-control/nginx-runtime
UNIT
cat >/usr/local/bin/cdnca-health-stub <<'STUB'
import http.server, sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()
STUB
for unit in cdnca-agent-gateway:8082 cdnca-control-api:8080; do
  printf '[Service]\nExecStart=/usr/bin/python3 /usr/local/bin/cdnca-health-stub %s\n' ${unit#*:} >/etc/systemd/system/${unit%%:*}.service
done
systemctl daemon-reload; systemctl start cdnca-control-web cdnca-agent-gateway cdnca-control-api
sleep 2
for unit in cdnca-control-web cdnca-agent-gateway cdnca-control-api; do systemctl is-active -q $unit || fail "$unit not active"; done
curl -sf --resolve "$IP:443:127.0.0.1" --cacert $PKI/root-ca-cert.pem https://$IP/healthz >/dev/null || fail 'IP healthz before bind'
snapshot() { for f in /etc/cdnca-control/control.env /etc/cdnca-control/nginx.conf $PKI/gateway-server.pem $DL/edge-agent/upgrade-trust.json $DL/node-install-defaults /var/lib/cdnca-control/runtime-config.js; do sha256sum $f; done; ls $PKI/bind-public-cert.pem 2>/dev/null || true; }

# ---- 失败回滚：nginx reload 前把证书路径改坏不可行，改为让网关重启失败（ExecStart 不存在）
cp /etc/systemd/system/cdnca-agent-gateway.service /tmp/gw.unit
printf '[Service]\nExecStart=/nonexistent\n' >/etc/systemd/system/cdnca-agent-gateway.service; systemctl daemon-reload
BEFORE=$(snapshot)
if "$BIN" control-host bind --domain $DOMAIN --cert-file /tmp/op-chain.pem --key-file /tmp/op.key --skip-dns-check >/tmp/bind-fail.log 2>&1; then fail 'bind should fail when the Gateway cannot restart'; fi
grep -q 'rolled back\|ROLLBACK' /tmp/bind-fail.log || { cat /tmp/bind-fail.log; fail 'no rollback message'; }
cp /tmp/gw.unit /etc/systemd/system/cdnca-agent-gateway.service; systemctl daemon-reload; systemctl restart cdnca-agent-gateway
[ "$(snapshot)" = "$BEFORE" ] || { diff <(echo "$BEFORE") <(snapshot); fail 'files not restored after failed bind'; }
grep -q "rolled back" /tmp/bind-fail.log && pass "失败回滚：网关重启失败后文件全部恢复（$(grep -o 'host-bind-backup-[^)]*' /tmp/bind-fail.log | head -1)）"
curl -sf --resolve "$IP:443:127.0.0.1" --cacert $PKI/root-ca-cert.pem https://$IP/healthz >/dev/null || fail 'IP healthz after rollback'

# ---- 正常绑定（证书文件，跳过 DNS 预检：容器无公网解析）
"$BIN" control-host bind --domain $DOMAIN --cert-file /tmp/op-chain.pem --key-file /tmp/op.key --skip-dns-check >/tmp/bind.log 2>/tmp/bind.err || { cat /tmp/bind.log /tmp/bind.err; fail bind; }
cat /tmp/bind.log
# 浏览器按域名（SNI）拿到运营者证书
served=$(echo | openssl s_client -connect 127.0.0.1:443 -servername $DOMAIN 2>/dev/null | openssl x509 -noout -fingerprint -sha256)
[ "$served" = "$(openssl x509 -in /tmp/op.crt -noout -fingerprint -sha256)" ] && pass "域名 SNI 返回绑定证书" || fail "domain SNI served $served"
curl -sf --resolve "$DOMAIN:443:127.0.0.1" --cacert /tmp/op-ca.pem https://$DOMAIN/healthz >/dev/null && pass '域名 https 健康检查' || fail 'domain healthz'
# 节点按 IP 无 SNI / IP SNI 仍拿私有证书
curl -sf --resolve "$IP:443:127.0.0.1" --cacert $PKI/root-ca-cert.pem https://$IP/healthz >/dev/null && pass 'IP 访问仍用私有证书' || fail 'IP healthz after bind'
nosni=$(echo | openssl s_client -connect 127.0.0.1:443 -noservername 2>/dev/null | openssl x509 -noout -issuer)
case $nosni in *'CDNCA local control root'*) pass '无 SNI 连接拿私有证书（节点升级下载不变）' ;; *) fail "no-SNI issuer $nosni" ;; esac
# 网关证书 SAN 含 IP+域名，私钥未变
openssl x509 -in $PKI/gateway-server.pem -noout -checkip $IP | grep -q 'does match' && openssl x509 -in $PKI/gateway-server.pem -noout -checkhost $DOMAIN | grep -q 'does match' &&
  openssl verify -CAfile $PKI/root-ca-cert.pem $PKI/gateway-server.pem >/dev/null && pass "网关证书 SAN: $(openssl x509 -in $PKI/gateway-server.pem -noout -ext subjectAltName | tail -1 | xargs)" || fail 'gateway SAN'
[ "$(openssl pkey -in $PKI/gateway-server-key.pem -pubout | sha256sum)" = "$GW_KEY_BEFORE" ] && pass '网关私钥未变' || fail 'gateway key changed'
grep -qx "PAYMENT_CHANNELS_NOTIFY_BASE=https://$DOMAIN" /etc/cdnca-control/control.env && grep -qx "CDNCA_GATEWAY_LOCAL_ADDRESS=$DOMAIN:19444" /etc/cdnca-control/control.env &&
  grep -qx "CONTROL_UPGRADE_ARTIFACT_BASE_URL=https://$IP/downloads/edge-agent/upgrades/sha256" /etc/cdnca-control/control.env && pass 'control.env 地址更新、升级下载地址保持 IP' || fail control.env
grep -qx "gateway_address=$DOMAIN:19444" $DL/node-install-defaults && grep -qx "gateway_server_name=$DOMAIN" $DL/node-install-defaults && pass 'node-install-defaults 改用域名' || fail defaults
grep -q "__CDNCA_GATEWAY_SERVER_NAME__ = \"$DOMAIN\"" /var/lib/cdnca-control/runtime-config.js && pass 'runtime-config.js 网关改用域名' || fail runtime
NEW_SHA=$(sed -n 's/^upgrade_trust_sha256=//p' $DL/node-install-defaults)
[ "$NEW_SHA" = "$(sha256sum $DL/edge-agent/upgrade-trust.json | awk '{print $1}')" ] && grep -q "__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = \"$NEW_SHA\"" /var/lib/cdnca-control/runtime-config.js && pass "信任文档指纹一致 $NEW_SHA" || fail trust-sha
# 测试证书不受系统信任：CA 指纹保留
grep -q "__CDNCA_CONTROL_CA_SHA256__ = \"$CA_SHA\"" /var/lib/cdnca-control/runtime-config.js && pass '非公网受信证书时保留 CA 指纹' || fail ca-pin
"$BIN" control-host status >/tmp/status.log && grep -q "已绑定域名 / bound domain: $DOMAIN" /tmp/status.log && pass 'control-host status' || { cat /tmp/status.log; fail status; }
cat /tmp/status.log
# 幂等
AFTER=$(snapshot)
"$BIN" control-host bind --domain $DOMAIN --cert-file /tmp/op-chain.pem --key-file /tmp/op.key --skip-dns-check >/tmp/bind2.log 2>&1 || { cat /tmp/bind2.log; fail rebind; }
grep -q 'nothing changed' /tmp/bind2.log && [ "$(snapshot)" = "$AFTER" ] && pass '重复执行无改动' || { cat /tmp/bind2.log; fail idempotent; }
# 升级时的 nginx 收敛脚本对绑定后的配置稳定
python3 /tmp/converge.py check 2>&1 | tail -1 | grep -q 'already converged' && pass 'converge-management-web-nginx.py check：already converged' || { python3 /tmp/converge.py check | head -20; fail converge; }
echo ALL-PASS

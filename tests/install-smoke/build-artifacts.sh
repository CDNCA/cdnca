#!/usr/bin/env bash
# 为社区版主控全新安装冒烟构建本提交产物，只用一次性测试密钥签名（不连生产）。
# 产出 downloads/（control-native、edge-agent、install-control.sh 等），供 run.sh 静态发布站挂载。
# 不构建授权端、不依赖已删除的授权安装脚本或授权服务。
# 用法：tests/install-smoke/build-artifacts.sh <out>
# 产出：
#   <out>/downloads/                 冒烟发布站 /downloads 树
#   <out>/keys/release/              测试发布密钥（private.pem 只在本机）
# 可选环境变量：CDNCA_REMOTE_REF（默认 refs/heads/<当前分支>）、CDNCA_VERSION（默认 1.0.35）、
#   CDNCA_G3_MODSECURITY、STD_DIR、CDNCA_NATS_BUILD_DIR、CDNCA_OPENRESTY_ARCHIVE、CDNCA_SKIP=<阶段,...>

set -Eeuo pipefail
umask 022
trap 'printf "build-artifacts: 第 %s 行失败：%s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
OUT=${1:?usage: build-artifacts.sh <out>}
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd -P)
VERSION=${CDNCA_VERSION:-1.0.35}
COMMIT=$(git -C "$ROOT" rev-parse HEAD); TREE=$(git -C "$ROOT" rev-parse 'HEAD^{tree}')
REMOTE_REF=${CDNCA_REMOTE_REF:-refs/heads/$(git -C "$ROOT" branch --show-current)}
G3_MODSEC=${CDNCA_G3_MODSECURITY:?set CDNCA_G3_MODSECURITY to the amd64 ModSecurity build directory}
STD=${STD_DIR:-$HOME/.cache/cdnca-waf-datasets/corpus}
NATS_DIR=${CDNCA_NATS_BUILD_DIR:-$HOME/.cache/cdnca-release-inputs/nats}
OPENRESTY_ARCHIVE=${CDNCA_OPENRESTY_ARCHIVE:-$HOME/.cache/cdnca-release-inputs/tools/openresty-1.31.1.1.tar.gz}
DOWNLOAD_BASE=https://release.cdnca.smoke/downloads
SOURCE_REPOSITORY=${CE_SOURCE_REPOSITORY:-https://github.com/CDNCA/cdnca.git}
RUNTIME_IMAGE=cdnca-install-smoke-runtime:${COMMIT:0:12}
LOG=$OUT/logs; mkdir -p "$LOG"
log() { printf '[build-artifacts] %s %s\n' "$(date +%T)" "$*"; }
die() { printf '[build-artifacts] 错误：%s\n' "$*" >&2; exit 1; }
skip() { case ",${CDNCA_SKIP:-}," in *",$1,"*) return 0 ;; esac; return 1; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
step() { local name=$1; shift; log "$name"; "$@" >"$LOG/$name.log" 2>&1 || { tail -30 "$LOG/$name.log" >&2; die "$name 失败（$LOG/$name.log）"; }; }

[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] || die '工作区有未提交改动：打包只认已提交并推送的源码'
[ "$(git -C "$ROOT" ls-remote --exit-code origin "$REMOTE_REF" | cut -f1)" = "$COMMIT" ] || die "$COMMIT 不是远端 $REMOTE_REF 的头：先推送（或设 CDNCA_REMOTE_REF）"
# 前端 dist 用已装好的 node_modules（借用集成工作区），lockfile 必须一致。
NM=${CDNCA_NODE_MODULES_REPO:-$ROOT}
[ -d "$NM/node_modules" ] || die "缺 $NM/node_modules：pnpm -C $ROOT install --frozen-lockfile，或 CDNCA_NODE_MODULES_REPO=<已安装的同 lockfile 工作区>"
cmp -s "$NM/pnpm-lock.yaml" "$ROOT/pnpm-lock.yaml" || die "$NM/pnpm-lock.yaml 与本提交不同"
for f in "$NATS_DIR/nats-server-2.12.15-cdnca.1" "$NATS_DIR/NATS-LICENSE" "$OPENRESTY_ARCHIVE" "$STD/wafcomp-mal.jsonl.gz" "$STD/wafcomp-legit.jsonl.gz"; do
  [ -s "$f" ] || die "缺输入 $f"
done
file -b "$G3_MODSEC/modules/ngx_http_modsecurity_module.so" | grep -q x86-64 || die "$G3_MODSEC 不是 amd64 ModSecurity 扩展"

# ---- 一次性测试密钥：发布签名（Ed25519 PEM）
K=$OUT/keys/release
KEY_ID=$(cat "$K/key-id" 2>/dev/null || echo "install-smoke-$(date -u +%Y%m%d)")
if [ ! -s "$K/private.pem" ]; then
  rm -rf "$K"; mkdir -p "$K"; chmod 0700 "$OUT/keys" "$K"
  openssl genpkey -algorithm ed25519 -out "$K/private.pem" 2>/dev/null
  openssl pkey -in "$K/private.pem" -pubout -out "$K/public.pem"
  jq -n --arg id "$KEY_ID" --rawfile pem "$K/public.pem" '{version:1,keys:[{key_id:$id,public_key_pem:$pem}]}' >"$K/artifacts.json"
  printf '%s\n' "$KEY_ID" >"$K/key-id"
fi
# 换提交后，带源码身份的产物全部重建；运行时载荷只依赖 edge/openresty 输入，验收会逐项核对，可复用。
if [ -s "$OUT/BUILD" ] && [ "$(sed -n 's/^commit=//p' "$OUT/BUILD")" != "$COMMIT" ]; then
  rm -rf "$OUT/edge" "$OUT/edge-payload" "$OUT/node" "$OUT/bundle" "$OUT/runtime-evidence" "$OUT/upgrade" "$OUT/upgrade-signed" "$OUT/install"
fi
printf 'commit=%s\ntree=%s\nversion=%s\nkey_id=%s\nremote_ref=%s\n' "$COMMIT" "$TREE" "$VERSION" "$KEY_ID" "$REMOTE_REF" >"$OUT/BUILD"
log "commit $COMMIT version $VERSION key $KEY_ID → $OUT"
sign() { # <signing-data> <out.sig>: base64 签名（sign.sh 同格式）
  openssl pkeyutl -sign -rawin -inkey "$K/private.pem" -in "$1" -out "$2.raw"
  openssl pkeyutl -verify -pubin -rawin -inkey "$K/public.pem" -in "$1" -sigfile "$2.raw" >/dev/null
  openssl base64 -A -in "$2.raw" -out "$2"
}
# ---- amd64 原生运行时：本提交 fresh build（native-payload）与 G3 用的运行时镜像
RB=$OUT/runtime-build
# 本机构建副本（只在构建机网络/架构需要时）：CDNCA_APK_MIRROR 换 Alpine 源；非 x86_64 宿主把 h3probe
# 改为 BUILDPLATFORM 交叉编译（QEMU 下 go 构建不稳定）。验收绑定的是提交里的 Dockerfile 与输入哈希，
# 产物内容不变（release-prep 10-20 同样做法，12/12 通过）。
DOCKERFILE=$ROOT/edge/openresty/native/Dockerfile
if [ -n "${CDNCA_APK_MIRROR:-}" ] || [ "$(uname -m)" != x86_64 ]; then
  DOCKERFILE=$OUT/Dockerfile.native-local
  sed -e "${CDNCA_APK_MIRROR:+s#^RUN apk add #RUN sed -i \"s\#https\\\\?://dl-cdn.alpinelinux.org\#$CDNCA_APK_MIRROR\#\" /etc/apk/repositories \&\& apk add #}" \
    "$ROOT/edge/openresty/native/Dockerfile" >"$DOCKERFILE"
  if [ "$(uname -m)" != x86_64 ]; then
    python3 - "$DOCKERFILE" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
s, n = re.subn(r'^FROM (golang@sha256:[0-9a-f]+) AS h3probe$', r'FROM --platform=$BUILDPLATFORM \1 AS h3probe\nARG TARGETARCH', s, flags=re.M)
s, m = re.subn(r'^ENV CGO_ENABLED=0 GOOS=linux ', 'ENV GOARCH=${TARGETARCH} CGO_ENABLED=0 GOOS=linux ', s, flags=re.M)
assert n == 1 and m == 1, 'h3probe stage layout changed'
open(p, 'w').write(s)
PY
  fi
fi
# 载荷含 edge/openresty 的 Lua：该子树变了就重建（只看 h3probe 会复用旧 Lua，验收报 payload Lua differs）
RB_TREE=$(git -C "$ROOT" rev-parse "$COMMIT:edge/openresty")
if ! skip runtime && { [ ! -x "$RB/runtime/bin/h3probe" ] || [ "$(cat "$RB.tree" 2>/dev/null)" != "$RB_TREE" ]; }; then
  rm -rf "$RB"
  step runtime-payload docker buildx build --platform linux/amd64 -f "$DOCKERFILE" \
    --target native-payload --output "type=local,dest=$RB" "$ROOT"
  printf '%s\n' "$RB_TREE" >"$RB.tree"
fi
if ! docker image inspect "$RUNTIME_IMAGE" >/dev/null 2>&1; then
  step runtime-image docker buildx build --platform linux/amd64 -f "$DOCKERFILE" \
    --target runtime --load -t "$RUNTIME_IMAGE" "$ROOT"
fi

# ---- Go 构建镜像（edge helper 用）
GO_IMAGE=$(jq -er '.builder.image' "$ROOT/agents/edge-agent/packaging/build/contract.json")
MODCACHE=$(go env GOMODCACHE)

# ---- 节点：agent + helper（stage1）、载荷 + helper bundle + 运行时冒烟 + 验收 + 节点包（stage2/stage3）
E=$OUT/edge; P=$OUT/edge-payload; N=$OUT/node
if ! skip edge && [ ! -s "$N/SHA256SUMS" ]; then
  rm -rf "$E" "$P" "$N" "$OUT/bundle" "$OUT/runtime-evidence"; mkdir -p "$E/source" "$E/helper"
  git -C "$ROOT" archive "$COMMIT" | tar -x -C "$E/source"
  TS=$(git -C "$ROOT" log -1 --format=%ct "$COMMIT")
  step edge-agent bash -c "cd '$E/source' && bash scripts/edge-agent-release-build.sh --output-dir '$E/output' --arch amd64 \
    --version '$VERSION' --build-id '$COMMIT' --source-repository '$SOURCE_REPOSITORY' --source-commit '$COMMIT' --source-date-epoch '$TS'"
  step edge-helper docker run --rm --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,exec,size=2g -e HOME=/tmp/home -e GOCACHE=/tmp/go-cache \
    -e GOMODCACHE=/modcache -e GOPROXY=off -e GOWORK=off -e GOTOOLCHAIN=local -e LC_ALL=C -e TZ=UTC -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 \
    -v "$MODCACHE:/modcache:ro" -v "$E/source:/src:ro" -v "$E/helper:/out:rw" -w /src/agents/edge-agent "$GO_IMAGE" \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o /out/cdnca-edge-agent-helper ./packaging/helper/cmd/cdnca-edge-agent-helper
  mkdir -p "$P/bin" "$P/evidence"; cp -a "$RB/runtime" "$RB/lua" "$P/"
  for f in openresty-V.txt runtime-apk-inventory.txt runtime-build-inputs.sha256 runtime-export.json runtime-sources.lock.json source-verification.json; do
    cp -p "$RB/evidence/$f" "$P/evidence/"
  done
  install -m 0555 "$E/output/edge-agent" "$P/bin/edge-agent"
  install -m 0555 "$E/helper/cdnca-edge-agent-helper" "$P/bin/cdnca-edge-agent-helper"
  install -m 0444 "$E/output/edge-agent.provenance.json" "$E/output/edge-agent.spdx.json" "$P/evidence/"
  SP=$E/source/agents/edge-agent/packaging
  for f in scripts/install.sh scripts/lib.sh scripts/preflight.sh scripts/rollback.sh scripts/uninstall.sh scripts/upgrade.sh \
      systemd/cdnca-edge-agent.service systemd/cdnca-edge-agent-root.service systemd/cdnca-edge-agent-helper.service \
      systemd/cdnca-edge-agent-helper.socket sysusers/cdnca-edge-agent.conf tmpfiles/cdnca-edge-agent.conf \
      tmpfiles/cdnca-edge-agent-root.conf logrotate/cdnca-edge-agent config/agent.env config/config.example.json README.md; do
    mkdir -p "$P/packaging/$(dirname "$f")"; cp "$SP/$f" "$P/packaging/$f"
    case $f in scripts/*) chmod 0555 "$P/packaging/$f" ;; *) chmod 0444 "$P/packaging/$f" ;; esac
  done
  find "$P/packaging" -type d -exec chmod 0755 {} +
  step edge-bundle-prepare env GOWORK=off go -C "$ROOT/agents/edge-agent" run ./packaging/helper/cmd/cdnca-edge-release-bundle prepare \
    --release-dir "$E/output" --release-sequence 1 --output-dir "$OUT/bundle"
  sign "$OUT/bundle/manifest.signing-data" "$OUT/manifest.sig"
  step edge-bundle-finalize env GOWORK=off go -C "$ROOT/agents/edge-agent" run ./packaging/helper/cmd/cdnca-edge-release-bundle finalize \
    --prepared-dir "$OUT/bundle" --signature "$OUT/manifest.sig.raw" --public-key "$K/public.pem" --download-base-url "$DOWNLOAD_BASE"
  mkdir -p "$P/upgrade"; cp "$OUT/bundle/manifest" "$OUT/bundle/manifest.sig" "$P/upgrade/"; cp "$K/public.pem" "$P/upgrade/package-signing.pem"
  chmod 0444 "$P/upgrade/"*; chmod 0755 "$P/upgrade"
  # 运行时冒烟（stage2 在 68 跑；这里在 amd64 debian:12 容器里跑同一脚本）
  mkdir -p "$OUT/runtime-evidence"
  smoke_script=$ROOT/scripts/native-node-runtime-smoke.sh
  if [ "$(uname -m)" = arm64 ]; then
    # Rosetta 下进程 args 带翻译器前缀，worker 按 PPID 识别（只改识别方式，验收绑定的是仓库脚本哈希与结果）
    smoke_script=$OUT/native-node-runtime-smoke.rosetta.sh
    sed -e "s#ps -o pid=,args= --ppid \"\$SMOKE_MASTER\" | awk '/nginx: worker process\$/ {print \$1}'); \[\[#ps -o pid= --ppid \"\$SMOKE_MASTER\" | awk '{print \$1}'); [[#" \
      -e "s#worker_after=\$(ps -o pid=,args= --ppid \"\$SMOKE_MASTER\" | awk '/nginx: worker process\$/ {print \$1}')#worker_after=\$(ps -o pid= --ppid \"\$SMOKE_MASTER\" | awk -v old=\"\$worker_before\" '\$1 != old {print \$1}')#" \
      "$ROOT/scripts/native-node-runtime-smoke.sh" >"$smoke_script"
  fi
  step runtime-smoke docker run --rm --platform linux/amd64 --cap-add SYS_ADMIN --cap-add NET_ADMIN --security-opt apparmor=unconfined \
    --security-opt seccomp=unconfined -v "$P:/payload:ro" -v "$smoke_script:/smoke.sh:ro" -v "$OUT/runtime-evidence:/out" debian:12 bash -c "
      set -e; apt-get update -qq >/dev/null; apt-get install -y -qq curl jq openssl procps iproute2 python3 util-linux binutils >/dev/null
      PAYLOAD_DIR=/payload SOURCE_COMMIT=$COMMIT SOURCE_TREE=$TREE EVIDENCE_DIR=/out/evidence bash /smoke.sh"
  cp "$OUT/runtime-evidence/evidence/result.json" "$P/evidence/runtime-smoke.json"; chmod 0444 "$P/evidence/runtime-smoke.json"
  step runtime-acceptance bash -c "cd '$ROOT' && node scripts/native-node-runtime-acceptance.mjs --source-commit '$COMMIT' --payload-dir '$P' \
    --smoke-result '$OUT/runtime-evidence/evidence/result.json' --source-archive '$OPENRESTY_ARCHIVE'"
  step node-prepare bash -c "cd '$ROOT' && node scripts/native-node-package.mjs prepare --source-commit '$COMMIT' --remote-ref '$REMOTE_REF' \
    --version '$VERSION' --key-id '$KEY_ID' --payload-dir '$P' --output-dir '$N'"
  sign "$N/release.signing-data" "$OUT/node.sig"
  step node-finalize bash -c "cd '$ROOT' && node scripts/native-node-package.mjs finalize --build-dir '$N' --signature '$OUT/node.sig' --public-key '$K/public.pem'"
fi

# ---- 主控：基线内包（upgrade-package --baseline）→ 签名 finalize → 外包 prepare/签名/finalize（stage3、finalize-install）
U=$OUT/upgrade; US=$OUT/upgrade-signed; I=$OUT/install
if ! skip control && [ ! -s "$I/SHA256SUMS" ]; then
  rm -rf "$U" "$US" "$I"
  step control-baseline bash -c "cd '$ROOT' && node scripts/native-initial-release-package.mjs --baseline --source-commit '$COMMIT' \
    --remote-ref '$REMOTE_REF' --version '$VERSION' --arch amd64 --key-id '$KEY_ID' --output-dir '$U' --allow-empty-turnstile-site-key"
  sign "$U/release.signing-data" "$OUT/upgrade.sig"
  step control-finalize bash -c "cd '$ROOT' && node scripts/native-release-signature.mjs --build-dir '$U' --remote-ref '$REMOTE_REF' \
    --signature '$OUT/upgrade.sig' --public-key '$K/public.pem' --output-dir '$US'"
  step install-prepare bash -c "cd '$ROOT' && node scripts/native-control-install-package.mjs prepare --source-commit '$COMMIT' --remote-ref '$REMOTE_REF' \
    --initial-build-dir '$US' --nats-build-dir '$NATS_DIR' --key-id '$KEY_ID' --output-dir '$I' --artifact-public-key '$K/public.pem'"
  sign "$I/install.signing-data" "$OUT/install.sig"
  step install-finalize bash -c "cd '$ROOT' && node scripts/native-control-install-package.mjs finalize --build-dir '$I' --remote-ref '$REMOTE_REF' \
    --signature '$OUT/install.sig' --public-key '$K/public.pem' --artifact-public-key '$K/public.pem'"
fi

# ---- /downloads 树（assemble.sh）
D=$OUT/downloads
rm -rf "$D"; mkdir -p "$D/control-native/latest" "$D/edge-agent/latest" "$D/edge-agent/$VERSION" "$D/control-api/$VERSION"
install -m 0644 "$ROOT/scripts/install-control.sh" "$ROOT/scripts/install-node.sh" "$D/"
cp "$K/artifacts.json" "$D/control-native/artifacts.json"
jq -s -e '[.[].keys[]] as $k | select(($k | map(.key_id) | unique | length) == ($k | length)) | {version:1,keys:$k}' \
  "$ROOT/apps/web/edge-agent-artifacts.json" "$K/artifacts.json" >"$D/edge-agent/artifacts.json"
cp "$I/cdnca-control-native.tar" "$I/install.manifest.json" "$I/SHA256SUMS" "$D/control-native/latest/"
cp "$N/cdnca-edge-agent.tar.gz" "$N/SHA256SUMS" "$D/edge-agent/latest/"
cp "$N/release.manifest.json" "$D/edge-agent/latest/native.manifest.json"
cp "$US/native-management.tar" "$US/release.manifest.json" "$D/control-api/$VERSION/"
(cd "$D/control-api/$VERSION" && shasum -a 256 native-management.tar >SHA256SUMS)
[ "$(tar -xOf "$I/cdnca-control-native.tar" native-management.tar | shasum -a 256 | cut -d' ' -f1)" = "$(cut -d' ' -f1 "$D/control-api/$VERSION/SHA256SUMS")" ] ||
  die '外包内嵌的 native-management.tar 与 control-api 包不一致'
bn=$(jq -r .download_path "$OUT/bundle/bundle.json" | sed 's#.*/##'); cp "$OUT/bundle/$bn" "$D/edge-agent/$VERSION/"
cp "$N/cdnca-edge-agent.tar.gz" "$N/SHA256SUMS" "$D/edge-agent/$VERSION/"; chmod u+w "$D/edge-agent/$VERSION/SHA256SUMS"
(cd "$D/edge-agent/$VERSION" && shasum -a 256 "$bn" >>SHA256SUMS)
find "$D" -type d -exec chmod 0755 {} +; find "$D" -type f -exec chmod 0644 {} +
docker image rm "$RUNTIME_IMAGE" >/dev/null 2>&1 || true
(cd "$OUT" && find downloads -type f | LC_ALL=C sort | xargs shasum -a 256) >"$OUT/artifacts.sha256"
log "完成：$(wc -l <"$OUT/artifacts.sha256" | tr -d ' ') 个文件，清单 $OUT/artifacts.sha256"

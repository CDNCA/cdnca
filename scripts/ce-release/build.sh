#!/usr/bin/env bash
# cdncaCE 社区版发布构建入口：构建本提交的主控整包、节点包与发布站 /downloads 树。
# 步骤与 tests/install-smoke/build-artifacts.sh（商业版冒烟构建）相同，去掉授权端 STAGE 与离线根；
# 社区版没有授权端。签名两种方式：
#   默认：在 <out>/keys/release 现场生成一次性测试密钥（只用于冒烟，私钥只留在本机输出目录）
#   正式：CE_SIGNER=<命令> CE_PUBLIC_KEY=<公钥 PEM> CE_KEY_ID=<key id>，脚本对每份 signing-data 调用
#         "$CE_SIGNER <signing-data> <输出.sig.raw>"（原始 64 字节 Ed25519 签名），私钥不进构建机
# 用法：scripts/ce-release/build.sh <out>
# 产出：<out>/downloads/（发布站 /downloads 树：control-native、edge-agent、control-api、install-*.sh）
# 必填环境变量：CE_DOWNLOAD_BASE（发布站 /downloads 的 HTTPS 地址，写进节点升级包）、
#   CE_SOURCE_REPOSITORY（https 源码仓库地址，写进节点二进制来源证明；默认 https://github.com/CDNCA/cdnca.git）
# 官方发布公钥：CE_OFFICIAL_RELEASE_KEYS=<官方 artifacts.json>（默认 ~/.cache/cdnca-release-inputs/trust/<current-key-id>/artifacts.json）
# 节点 bootstrap 公钥：CE_BOOTSTRAP_PUBLIC_KEY=<PEM> CE_BOOTSTRAP_KEY_ID=<id>；不设时同测试签名，现场生成测试钥
# 可选：CDNCA_REMOTE_REF（默认 refs/heads/<当前分支>）、CDNCA_VERSION（默认 1.0.35）、
#   CDNCA_NATS_BUILD_DIR、CDNCA_OPENRESTY_ARCHIVE、CDNCA_SKIP=<runtime,edge,control>
set -Eeuo pipefail
umask 022
trap 'printf "ce-release: 第 %s 行失败：%s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
OUT=${1:?usage: scripts/ce-release/build.sh <out>}
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd -P)
VERSION=${CDNCA_VERSION:-1.0.35}
COMMIT=$(git -C "$ROOT" rev-parse HEAD); TREE=$(git -C "$ROOT" rev-parse 'HEAD^{tree}')
REMOTE_REF=${CDNCA_REMOTE_REF:-refs/heads/$(git -C "$ROOT" branch --show-current)}
NATS_DIR=${CDNCA_NATS_BUILD_DIR:-$HOME/.cache/cdnca-release-inputs/nats}
OPENRESTY_ARCHIVE=${CDNCA_OPENRESTY_ARCHIVE:-$HOME/.cache/cdnca-release-inputs/tools/openresty-1.31.1.1.tar.gz}
DOWNLOAD_BASE=${CE_DOWNLOAD_BASE:?CE_DOWNLOAD_BASE 必填：发布站 /downloads 的 HTTPS 地址}
SOURCE_REPOSITORY=${CE_SOURCE_REPOSITORY:-https://github.com/CDNCA/cdnca.git}
LOG=$OUT/logs; mkdir -p "$LOG"
log() { printf '[ce-release] %s %s\n' "$(date +%T)" "$*"; }
die() { printf '[ce-release] 错误：%s\n' "$*" >&2; exit 1; }
skip() { case ",${CDNCA_SKIP:-}," in *",$1,"*) return 0 ;; esac; return 1; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
step() { local name=$1; shift; log "$name"; "$@" >"$LOG/$name.log" 2>&1 || { tail -30 "$LOG/$name.log" >&2; die "$name 失败（$LOG/$name.log）"; }; }

[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] || die '工作区有未提交改动：打包只认已提交并推送的源码'
[ "$(git -C "$ROOT" ls-remote --exit-code origin "$REMOTE_REF" | cut -f1)" = "$COMMIT" ] || die "$COMMIT 不是远端 $REMOTE_REF 的头：先推送（或设 CDNCA_REMOTE_REF）"
for f in "$NATS_DIR/nats-server-2.12.15-cdnca.1" "$NATS_DIR/NATS-LICENSE" "$OPENRESTY_ARCHIVE"; do
  [ -s "$f" ] || die "缺输入 $f"
done

# ---- 签名密钥：正式发布用外部签名器（CE_SIGNER），否则一次性测试密钥
K=$OUT/keys/release
if [ -n "${CE_SIGNER:-}" ]; then
  KEY_ID=${CE_KEY_ID:?CE_SIGNER 需要 CE_KEY_ID}
  [ -s "${CE_PUBLIC_KEY:?CE_SIGNER 需要 CE_PUBLIC_KEY}" ] || die "缺公钥 $CE_PUBLIC_KEY"
  rm -rf "$K"; mkdir -p "$K"; chmod 0700 "$OUT/keys" "$K"
  cp "$CE_PUBLIC_KEY" "$K/public.pem"
  jq -n --arg id "$KEY_ID" --rawfile pem "$K/public.pem" '{version:1,keys:[{key_id:$id,public_key_pem:$pem}]}' >"$K/artifacts.json"
  printf '%s\n' "$KEY_ID" >"$K/key-id"
else
  KEY_ID=$(cat "$K/key-id" 2>/dev/null || echo "ce-smoke-$(date -u +%Y%m%d)")
  if [ ! -s "$K/private.pem" ]; then
    rm -rf "$K"; mkdir -p "$K"; chmod 0700 "$OUT/keys" "$K"
    openssl genpkey -algorithm ed25519 -out "$K/private.pem" 2>/dev/null
    openssl pkey -in "$K/private.pem" -pubout -out "$K/public.pem"
    jq -n --arg id "$KEY_ID" --rawfile pem "$K/public.pem" '{version:1,keys:[{key_id:$id,public_key_pem:$pem}]}' >"$K/artifacts.json"
    printf '%s\n' "$KEY_ID" >"$K/key-id"
  fi
fi
# ---- 官方发布公钥（节点验签官方制品用；只含公钥）
OFFICIAL_KEYS=${CE_OFFICIAL_RELEASE_KEYS:-$HOME/.cache/cdnca-release-inputs/trust/$(cat "$HOME/.cache/cdnca-release-inputs/trust/current-key-id" 2>/dev/null)/artifacts.json}
jq -e '.version == 1 and (.keys | length > 0) and all(.keys[]; (.public_key_pem | startswith("-----BEGIN PUBLIC KEY-----")) and (has("private_key_pem") | not))' \
  "$OFFICIAL_KEYS" >/dev/null 2>&1 || die "缺官方发布公钥清单 $OFFICIAL_KEYS（设 CE_OFFICIAL_RELEASE_KEYS）"
# ---- 社区版节点 bootstrap 公钥：CE_BOOTSTRAP_PUBLIC_KEY + CE_BOOTSTRAP_KEY_ID，否则一次性测试钥
BK=$OUT/keys/bootstrap
if [ -n "${CE_BOOTSTRAP_PUBLIC_KEY:-}" ]; then
  [ -s "$CE_BOOTSTRAP_PUBLIC_KEY" ] || die "缺 bootstrap 公钥 $CE_BOOTSTRAP_PUBLIC_KEY"
  BOOT_ID=${CE_BOOTSTRAP_KEY_ID:?CE_BOOTSTRAP_PUBLIC_KEY 需要 CE_BOOTSTRAP_KEY_ID}
  rm -rf "$BK"; mkdir -p "$BK"; chmod 0700 "$BK"
  cp "$CE_BOOTSTRAP_PUBLIC_KEY" "$BK/public.pem"
elif [ ! -s "$BK/private.pem" ]; then
  BOOT_ID=ce-edge-bootstrap-smoke-$(date -u +%Y%m%d)
  rm -rf "$BK"; mkdir -p "$BK"; chmod 0700 "$BK"
  openssl genpkey -algorithm ed25519 -out "$BK/private.pem" 2>/dev/null
  openssl pkey -in "$BK/private.pem" -pubout -out "$BK/public.pem"
else
  BOOT_ID=$(cat "$BK/key-id")
fi
printf '%s\n' "$BOOT_ID" >"$BK/key-id"
jq -n --arg id "$BOOT_ID" --rawfile pem "$BK/public.pem" '{version:1,keys:[{key_id:$id,public_key_pem:$pem}]}' >"$BK/artifacts.json"
[ "$BOOT_ID" != cdnca-edge-artifact-bootstrap-v1 ] || die '社区版不得使用商业版节点 bootstrap 钥'
# 换提交后，带源码身份的产物全部重建；运行时载荷只依赖 edge/openresty 输入，验收会逐项核对，可复用。
if [ -s "$OUT/BUILD" ] && [ "$(sed -n 's/^commit=//p' "$OUT/BUILD")" != "$COMMIT" ]; then
  rm -rf "$OUT/edge" "$OUT/edge-payload" "$OUT/node" "$OUT/bundle" "$OUT/runtime-evidence" "$OUT/upgrade" "$OUT/upgrade-signed" "$OUT/install"
fi
printf 'commit=%s\ntree=%s\nversion=%s\nkey_id=%s\nremote_ref=%s\n' "$COMMIT" "$TREE" "$VERSION" "$KEY_ID" "$REMOTE_REF" >"$OUT/BUILD"
log "commit $COMMIT version $VERSION key $KEY_ID → $OUT"
sign() { # <signing-data> <out.sig>: base64 签名（sign.sh 同格式），落盘前用公钥验证
  if [ -n "${CE_SIGNER:-}" ]; then
    "$CE_SIGNER" "$1" "$2.raw" || die "外部签名失败：$1"
  else
    openssl pkeyutl -sign -rawin -inkey "$K/private.pem" -in "$1" -out "$2.raw"
  fi
  openssl pkeyutl -verify -pubin -rawin -inkey "$K/public.pem" -in "$1" -sigfile "$2.raw" >/dev/null
  openssl base64 -A -in "$2.raw" -out "$2"
}

# ---- amd64 原生运行时：本提交 fresh build（native-payload）
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
# 节点信任清单 = 社区版节点 bootstrap 钥 + 本次发布钥 + 官方发布公钥（官方经制品集下发的
# CRS 引擎模块、IP 库等由它签名）；不含商业版 cdnca-edge-artifact-bootstrap-v1
jq -s -e '[.[].keys[]] as $k | select(($k | map(.key_id) | unique | length) == ($k | length)) | {version:1,keys:$k}' \
  "$BK/artifacts.json" "$K/artifacts.json" "$OFFICIAL_KEYS" >"$D/edge-agent/artifacts.json"
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
(cd "$OUT" && find downloads -type f | LC_ALL=C sort | xargs shasum -a 256) >"$OUT/artifacts.sha256"
log "完成：$(wc -l <"$OUT/artifacts.sha256" | tr -d ' ') 个文件，清单 $OUT/artifacts.sha256"

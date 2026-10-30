#!/usr/bin/env bash
# 开发套件无源码验收（fix-devkit-pub，DEV-PLUG-01/A 交付门槛）：在一个没有平台源码的临时目录里，
# 完全按卖家文档「脚手架、本地预览与打包」与官网教程的命令操作：
#   下载 cdnca-dev-kit.tar.gz、dev-kit.manifest.json、SHA256SUMS → sha256sum -c → 解包 → cat VERSION SOURCE →
#   主题工具 / 页面 SDK 自测 → init 新主题 → check → pack → cdnca-plugin sign-manifest（一次性密钥）→
#   示例主题 shield-blue 预检打包 → Webhook 接收器与 provider 参考实现 go test（GOWORK=off，只用套件内文件）。
# 下载源二选一：
#   DEV_KIT_BASE=https://developer.cdnca.com/downloads   线上卖家站（发布后验收）
#   DEV_KIT_SITE=<目录>                                   本地下载站目录（含 downloads/dev-kit 与
#                                                         downloads/cdnca-plugin），用本机 python3 静态服务模拟
# 另需 cdnca-plugin：同一下载源的 downloads/cdnca-plugin/（按本机平台选文件、按 SHA256SUMS 校验）。
# 可选 EXPECT_VERSION、EXPECT_COMMIT：与套件 VERSION / SOURCE 比对。KEEP=1 保留工作目录。
# 不读任何密钥文件；签名用本次生成并随目录删除的一次性密钥。
set -Eeuo pipefail
W=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-dev-kit-acceptance.XXXXXX"); W=$(cd "$W" && pwd -P)
SERVER=''
cleanup() { [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true; [ "${KEEP:-0}" = 1 ] || rm -rf -- "$W"; }
trap cleanup EXIT
step() { printf '\n==== %s\n' "$*"; }
die() { printf '!!!! 验收失败：%s\n' "$*" >&2; exit 1; }
sumc() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

if [ -n "${DEV_KIT_SITE:-}" ]; then
  [ -d "$DEV_KIT_SITE/downloads/dev-kit" ] || die "$DEV_KIT_SITE 下没有 downloads/dev-kit（不是带下载的站点目录）"
  port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
  python3 -m http.server "$port" --bind 127.0.0.1 --directory "$DEV_KIT_SITE" >"$W/http.log" 2>&1 & SERVER=$!
  for _ in $(seq 1 50); do curl -fsS -o /dev/null "http://127.0.0.1:$port/downloads/dev-kit/SHA256SUMS" 2>/dev/null && break; sleep 0.1; done
  BASE=http://127.0.0.1:$port/downloads
else
  BASE=${DEV_KIT_BASE:?set DEV_KIT_BASE (https://<site>/downloads) or DEV_KIT_SITE (local download site dir)}
fi
mkdir "$W/author"; cd "$W/author"
# 这个目录里没有平台源码：确认上层也不是 git 仓库，套件不能偷偷用到源码树。
! git rev-parse --show-toplevel >/dev/null 2>&1 || die "$W 在 git 仓库里"

step "下载、校验、解包（卖家文档命令，下载源 $BASE）"
CDNCA_KIT="$BASE/dev-kit"
curl --fail --location --show-error --output cdnca-dev-kit.tar.gz "$CDNCA_KIT/cdnca-dev-kit.tar.gz"
curl --fail --location --show-error --output dev-kit.manifest.json "$CDNCA_KIT/dev-kit.manifest.json"
curl --fail --location --show-error --output SHA256SUMS "$CDNCA_KIT/SHA256SUMS"
sumc -c SHA256SUMS
tar -xzf cdnca-dev-kit.tar.gz
cd cdnca-dev-kit && cat VERSION SOURCE
V=$(cat VERSION); C=$(sed -n 's/^commit //p' SOURCE)
[ -z "${EXPECT_VERSION:-}" ] || [ "$V" = "$EXPECT_VERSION" ] || die "VERSION $V != $EXPECT_VERSION"
[ -z "${EXPECT_COMMIT:-}" ] || [ "$C" = "$EXPECT_COMMIT" ] || die "SOURCE commit $C != $EXPECT_COMMIT"
node -e 'const m=JSON.parse(require("fs").readFileSync("../dev-kit.manifest.json"));const[v,c]=process.argv.slice(1);if(m.version!==v||m.source.commit!==c)process.exit(1)' "$V" "$C" ||
  die 'dev-kit.manifest.json 与包内 VERSION/SOURCE 不一致'
KIT=$(pwd -P)

step "下载 cdnca-plugin（按本机平台）"
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) P=cdnca-plugin-linux-amd64 ;; Linux/aarch64|Linux/arm64) P=cdnca-plugin-linux-arm64 ;;
  Darwin/arm64) P=cdnca-plugin-darwin-arm64 ;; *) die "本机平台没有 cdnca-plugin 下载" ;;
esac
(cd "$W/author" && curl -fsSLO "$BASE/cdnca-plugin/$P" && curl -fsSL -o plugin.SHA256SUMS "$BASE/cdnca-plugin/SHA256SUMS" &&
  grep " $P\$" plugin.SHA256SUMS | sumc -c - && chmod +x "$P" && mv "$P" cdnca-plugin)
CLI=$W/author/cdnca-plugin

step "主题工具与页面 SDK 自测（套件 README 命令）"
node --test packages/site-theme-kit/test/kit.test.mjs packages/site-theme-kit/test/entrypoint.test.mjs >"$W/kit-test.log" 2>&1 ||
  { tail -20 "$W/kit-test.log"; die '主题工具自测失败'; }
grep -E '^ℹ (pass|fail)' "$W/kit-test.log"
node --test docs/developer/examples/plugin-ui-sdk/sdk.test.mjs >"$W/sdk-test.log" 2>&1 || { tail -20 "$W/sdk-test.log"; die '页面 SDK 自测失败'; }
grep -E '^ℹ (pass|fail)' "$W/sdk-test.log"

step "生成、预检、打包、签名一个新主题（官网教程命令）"
CDNCA_THEME_TOOL="$KIT/packages/site-theme-kit/bin/cdnca-site-theme.mjs"
"$CLI" keygen -out "$W/author/publisher.key" >/dev/null
node "$CDNCA_THEME_TOOL" init "$W/author/ocean" --template user+site --plugin-id com.example.ocean --name Ocean
(cd "$W/author/ocean" && node "$CDNCA_THEME_TOOL" check && node "$CDNCA_THEME_TOOL" pack &&
  "$CLI" sign-manifest -key "$W/author/publisher.key" -in dist/manifest.json -out dist/manifest.signed.json)
for f in theme.json schemas/config.schema.json manifest.json manifest.signed.json; do
  [ -s "$W/author/ocean/dist/$f" ] || die "pack 没有产出 dist/$f"
done
node -e 'const m=JSON.parse(require("fs").readFileSync(process.argv[1]));if(m.metadata?.id!=="com.example.ocean"||!m.integrity?.signature)process.exit(1)' "$W/author/ocean/dist/manifest.signed.json" ||
  die 'manifest.signed.json 不是 com.example.ocean 或没有 integrity'

step "示例主题 shield-blue 预检与打包"
cp -R examples/site-themes/shield-blue "$W/author/shield-blue"
(cd "$W/author/shield-blue" && node "$CDNCA_THEME_TOOL" check && node "$CDNCA_THEME_TOOL" pack --out "$W/author/shield-blue-dist")
[ -s "$W/author/shield-blue-dist/manifest.json" ] || die 'shield-blue 没有打出 manifest.json'

step "Webhook 接收器与 provider 参考实现（Go，只用套件内文件）"
if command -v go >/dev/null; then
  for m in examples/plugins/webhook-v2-receiver libs/entitlement/pluginprovider; do
    (cd "$m" && GOWORK=off GOFLAGS=-mod=mod GOPROXY=off go test ./... -count=1) >"$W/go-$(basename "$m").log" 2>&1 ||
      { tail -20 "$W/go-$(basename "$m").log"; die "$m go test 失败"; }
    tail -1 "$W/go-$(basename "$m").log"
  done
else
  echo '本机没有 go，跳过（套件 README 要求 Go 1.27）'
fi
printf '\n==== 开发套件无源码验收通过：VERSION %s，SOURCE commit %s，下载源 %s\n' "$V" "$C" "$BASE"

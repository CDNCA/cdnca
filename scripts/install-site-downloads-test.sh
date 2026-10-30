#!/usr/bin/env bash
# install-site.sh 卖家站下载门禁（fix-devkit-pub）本机单测，不要 root、不要 docker：
# --seller-dir 必须带已验签市场包里的 downloads/dev-kit/（cdnca-dev-kit.tar.gz、dev-kit.manifest.json、SHA256SUMS）
# 与 downloads/cdnca-plugin/SHA256SUMS，摘要逐个核对；缺任何一项或摘要不符都拒绝安装，
# 避免再出现“文档给了命令、发布根缺包、公网 404”。
set -Eeuo pipefail
REPO=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf -- "$T"' EXIT
FAILED=0
# shellcheck source=install-site.sh
CDNCA_SITE_SOURCE_ONLY=1 . "$REPO/scripts/install-site.sh"
set +e
sum() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
fixture() { # <dir>：一份完整的卖家站目录
  mkdir -p "$1/assets" "$1/downloads/dev-kit" "$1/downloads/cdnca-plugin"
  printf '<!doctype html>\n' >"$1/index.html"
  printf 'kit\n' >"$1/downloads/dev-kit/cdnca-dev-kit.tar.gz"
  printf '{}\n' >"$1/downloads/dev-kit/dev-kit.manifest.json"
  (cd "$1/downloads/dev-kit" && sum cdnca-dev-kit.tar.gz dev-kit.manifest.json >SHA256SUMS)
  printf 'bin\n' >"$1/downloads/cdnca-plugin/cdnca-plugin-linux-amd64"
  (cd "$1/downloads/cdnca-plugin" && sum cdnca-plugin-linux-amd64 >SHA256SUMS)
}
case_() { # <期望退出码> <说明> <准备命令>
  local d=$T/$RANDOM$RANDOM got
  fixture "$d"; (cd "$d" && eval "$3")
  (seller_downloads_ok "$d") >"$T/out" 2>&1; got=$?
  if [ "$got" = "$1" ]; then printf 'ok   %s\n' "$2"; else printf 'FAIL %s（退出 %s，期望 %s）\n' "$2" "$got" "$1"; sed 's/^/     /' "$T/out"; FAILED=1; fi
}
case_ 0 '完整的开发套件与签名工具' ':'
case_ 1 '缺开发套件包' 'rm downloads/dev-kit/cdnca-dev-kit.tar.gz'
case_ 1 '缺来源清单' 'rm downloads/dev-kit/dev-kit.manifest.json'
case_ 1 '缺开发套件 SHA256SUMS' 'rm downloads/dev-kit/SHA256SUMS'
case_ 1 '开发套件 SHA256SUMS 没列来源清单' 'sed -i.bak "/dev-kit.manifest.json/d" downloads/dev-kit/SHA256SUMS && rm downloads/dev-kit/SHA256SUMS.bak'
case_ 1 '开发套件包被改过' 'printf x >>downloads/dev-kit/cdnca-dev-kit.tar.gz'
case_ 1 '整个 downloads 缺失（只拷了 dist）' 'rm -rf downloads'
case_ 1 '缺签名工具 SHA256SUMS' 'rm downloads/cdnca-plugin/SHA256SUMS'
case_ 1 '签名工具被改过' 'printf x >>downloads/cdnca-plugin/cdnca-plugin-linux-amd64'
[ "$FAILED" = 0 ] && echo 'install-site 卖家站下载门禁：全部通过' || { echo 'install-site 卖家站下载门禁：有失败'; exit 1; }

#!/usr/bin/env bash
# 打包财务系统模块，lib/ 均为 php-sdk/src 的拷贝：
#   dist/cdnca-whmcs.zip     modules/servers/cdnca/{cdnca.php,templates/,lib/}
#   dist/cdnca-zjmf.zip      modules/servers/cdnca/{cdnca.php,templates/,lib/,README.md}（智简魔方老版财务系统）
#   dist/cdnca-zjmf-v10.zip  public/plugins/server/cdnca/{Cdnca.php,route.php,controller/,logic/,lang/,template/,lib/}（V10 业务系统）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

# pack <zip 名> <stage 目录> <zip 内顶层路径...>
pack() {
    local name="$1" stage="$2"
    shift 2
    rm -f "$DIST/$name"
    (cd "$stage" && zip -qrX "$DIST/$name" "$@")
    echo "$DIST/$name"
}

# ---- WHMCS
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
MODULE="$STAGE/whmcs/modules/servers/cdnca"
mkdir -p "$MODULE/lib"
cp "$ROOT/whmcs/modules/servers/cdnca/cdnca.php" "$MODULE/"
cp -R "$ROOT/whmcs/modules/servers/cdnca/templates" "$MODULE/"
cp "$ROOT/php-sdk/src/"*.php "$MODULE/lib/"
cp "$ROOT/whmcs/README.md" "$STAGE/whmcs/README.md"
pack cdnca-whmcs.zip "$STAGE/whmcs" modules README.md

# ---- 智简魔方老版财务系统
MODULE="$STAGE/zjmf/modules/servers/cdnca"
mkdir -p "$MODULE/lib"
cp "$ROOT/zjmf/modules/servers/cdnca/cdnca.php" "$MODULE/"
cp -R "$ROOT/zjmf/modules/servers/cdnca/templates" "$MODULE/"
cp "$ROOT/php-sdk/src/"*.php "$MODULE/lib/"
cp "$ROOT/zjmf/README.md" "$MODULE/README.md"
cp "$ROOT/zjmf/README.md" "$STAGE/zjmf/README.md"
pack cdnca-zjmf.zip "$STAGE/zjmf" modules README.md

# ---- 智简魔方 V10 业务系统
MODULE="$STAGE/zjmf-v10/public/plugins/server/cdnca"
mkdir -p "$MODULE"
cp -R "$ROOT/zjmf-v10/public/plugins/server/cdnca/." "$MODULE/"
mkdir -p "$MODULE/lib"
cp "$ROOT/php-sdk/src/"*.php "$MODULE/lib/"
cp "$ROOT/zjmf-v10/README.md" "$STAGE/zjmf-v10/README.md"
pack cdnca-zjmf-v10.zip "$STAGE/zjmf-v10" public README.md

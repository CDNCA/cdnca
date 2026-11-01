#!/usr/bin/env bash
# 从 assets/brand/cdnca/*.svg 导出全部默认品牌资源到各前端 public/（fix-brandkit）。
# 依赖：rsvg-convert（librsvg）、magick（ImageMagick 7）。登录页广告的中文用系统字体
# Hiragino Sans GB / PingFang SC 渲染，换机器导出前先确认字体存在；导出结果已入库，构建不依赖本脚本。
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
src="$root/assets/brand/cdnca"
web="$root/apps/web/public"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

png() { rsvg-convert -w "$2" -h "$3" "$src/$1" -o "$4"; }
# 去掉 PNG 里的时间戳等文本块，让重复导出字节一致。
strip() { magick "$1" -strip -define png:exclude-chunks=date,time "$1"; }

png logo.svg 288 92 "$web/logo.png"
png logo.svg 576 184 "$web/logo@2x.png"
png logo-dark.svg 288 92 "$web/logo-dark.png"
png logo-dark.svg 576 184 "$web/logo-dark@2x.png"
for size in 16 32 48 64; do png mark.svg "$size" "$size" "$tmp/mark-$size.png"; done
cp "$tmp/mark-64.png" "$web/favicon.png"
magick "$tmp/mark-16.png" "$tmp/mark-32.png" "$tmp/mark-48.png" "$web/favicon.ico"
cp "$src/mark.svg" "$web/favicon.svg"
for size in 512 192 180; do png app-icon.svg "$size" "$size" "$web/app-icon-$size.png"; done
png login-ad.svg 1024 1120 "$tmp/ad.png"
magick "$tmp/ad.png" -strip -quality 88 -sampling-factor 4:2:0 "$web/ad.jpeg"
# 英文/繁体广告：同一图形层，只把 login-ad.svg 的 <text> 行换成 login-ad-<语言>.text。
for lang in en zh-TW; do
  grep -v '^<text' "$src/login-ad.svg" \
    | awk -v layer="$src/login-ad-$lang.text" '/^<\/svg>/ { while ((getline line < layer) > 0) print line } { print }' > "$tmp/ad-$lang.svg"
  rsvg-convert -w 1024 -h 1120 "$tmp/ad-$lang.svg" -o "$tmp/ad-$lang.png"
  magick "$tmp/ad-$lang.png" -strip -quality 88 -sampling-factor 4:2:0 "$web/ad-$lang.jpeg"
done
png login-background.svg 1920 1080 "$tmp/bg.png"
magick "$tmp/bg.png" -strip -quality 86 -sampling-factor 4:2:0 "$web/login-background.jpeg"
for f in "$web"/logo*.png "$web"/favicon.png "$web"/app-icon-*.png; do strip "$f"; done

# 其它前端只需要图标：www public/ 的 SVG/PNG（社区版没有官网 apps/control-site）。
cp "$src/mark.svg" "$root/apps/www/public/favicon.svg"
cp "$web/favicon.png" "$root/apps/www/public/favicon.png"
echo "exported cdnca brand assets"

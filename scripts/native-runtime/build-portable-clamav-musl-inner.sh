#!/bin/sh
# Runs inside the pinned Alpine builder; see build-portable-clamav-musl.sh.
set -eu
version=1.4.6
release=https://github.com/Cisco-Talos/clamav/releases/download/clamav-$version
# Digest GitHub publishes for the release asset.
source_sha256=06dbc7adf96e2f6a27c548a841ce83c95360d1e121b106a6f7cf56f282a3c61b
prefix=/opt/cdnca-clamav-1.4
loader=$prefix/lib/ld-musl-x86_64.so.1
export SOURCE_DATE_EPOCH=1792108800 CARGO_NET_OFFLINE=true
apk add -q --no-cache build-base cmake ninja rust cargo python3 patchelf file curl tar coreutils findutils linux-headers \
  bzip2-dev check-dev curl-dev json-c-dev libxml2-dev ncurses-dev openssl-dev pcre2-dev zlib-dev >/dev/null
cd /tmp
for attempt in 1 2 3 4 5; do curl -fsSL -o clamav.tar.gz "$release/clamav-$version.tar.gz" && break; sleep 3; done
echo "$source_sha256  clamav.tar.gz" | sha256sum -c -
tar -xzf clamav.tar.gz
# The release tarball vendors every Rust crate; the build never touches the network.
cmake -S clamav-$version -B build -G Ninja -D CMAKE_BUILD_TYPE=Release \
  -D CMAKE_INSTALL_PREFIX=$prefix -D CMAKE_INSTALL_LIBDIR=lib64 \
  -D APP_CONFIG_DIRECTORY=/etc/clamav -D DATABASE_DIRECTORY=/var/lib/clamav \
  -D ENABLE_TESTS=OFF -D ENABLE_MILTER=OFF -D ENABLE_CLAMONACC=OFF -D ENABLE_SYSTEMD=OFF \
  -D ENABLE_MAN_PAGES=OFF -D ENABLE_EXAMPLES=OFF -D ENABLE_STATIC_LIB=OFF \
  -D CMAKE_C_FLAGS="-ffile-prefix-map=/tmp=." -D CMAKE_CXX_FLAGS="-ffile-prefix-map=/tmp=." >/tmp/cmake.log 2>&1 \
  || { tail -30 /tmp/cmake.log; exit 1; }
RUSTFLAGS="--remap-path-prefix=/tmp=." cmake --build build -- -j2 >/tmp/build.log 2>&1 \
  || { grep -nE "error(\[|:)|FAILED|Killed|signal" /tmp/build.log | head -40; exit 1; }
DESTDIR=/tmp/install cmake --install build >/dev/null
source=/tmp/install$prefix
root=/tmp/stage$prefix
mkdir -p "$root/bin" "$root/sbin" "$root/lib" "$root/lib64" "$root/share/doc"
cp -a "$source/sbin/clamd" "$root/sbin/"
cp -a "$source/bin/freshclam" "$source/bin/clamdscan" "$source/bin/clamscan" "$source/bin/clamconf" "$root/bin/"
cp -a "$source"/lib64/*.so* "$root/lib64/"
# Bundle every library the binaries reach, except musl itself (the loader is libc).
for pass in 1 2 3; do
  find "$root" -type f | while read -r path; do
    file -b "$path" | grep -q ELF || continue
    LD_LIBRARY_PATH="$root/lib64" ldd "$path" 2>/dev/null | awk '$2 == "=>" && $3 ~ /^\// { print $1, $3 }'
  done | sort -u | while read -r name target; do
    case "$target" in /lib/ld-musl-*|"$root"/*) continue ;; esac
    [ -e "$root/lib64/$name" ] || cp -L "$target" "$root/lib64/$name"
  done
done
cp -L /lib/ld-musl-x86_64.so.1 "$root/lib/ld-musl-x86_64.so.1"
find "$root" -type f | while read -r path; do
  file -b "$path" | grep -q ELF || continue
  [ "$path" = "$root/lib/ld-musl-x86_64.so.1" ] && continue
  strip --strip-unneeded "$path"
  case "$path" in
    "$root"/bin/*|"$root"/sbin/*) patchelf --set-interpreter "$loader" --force-rpath --set-rpath '$ORIGIN/../lib64' "$path" ;;
    *) patchelf --force-rpath --set-rpath '$ORIGIN' "$path" ;;
  esac
done
# Prove nothing resolves outside the prefix, then run it from the final path.
mkdir -p "$(dirname "$prefix")" && cp -a "$root" "$prefix"
for path in "$prefix"/bin/* "$prefix"/sbin/*; do
  env -i "$path" --version >/dev/null
done
env -i "$prefix/bin/clamscan" --version
if env -i "$prefix/lib/ld-musl-x86_64.so.1" --list "$prefix/sbin/clamd" | awk '$2 == "=>" { print $3 }' | grep -v "^$prefix/"; then
  echo "library resolved outside $prefix" >&2; exit 1
fi
curl -fsSL -o "$root/share/doc/COPYING.txt" "https://raw.githubusercontent.com/Cisco-Talos/clamav/clamav-$version/COPYING.txt"
apk info -v 2>/dev/null | sort >/tmp/apk-versions.txt
{
  printf 'ClamAV %s (GPL-2.0) built from %s/clamav-%s.tar.gz (sha256 %s)\n' "$version" "$release" "$version" "$source_sha256"
  printf 'against musl in alpine:3.22; bundled libraries come from these Alpine packages:\n'
  cat /tmp/apk-versions.txt
} >"$root/share/doc/SOURCE.txt"
find "$root" -exec touch -h -d 2026-10-17T00:00:00Z {} +
# Archive root is the prefix's last component, as in build-portable-clamav.sh.
cd "/tmp/stage$(dirname "$prefix")"
find "$(basename "$prefix")" -print0 | LC_ALL=C sort -z >/tmp/files
tar --null --no-recursion -T /tmp/files --owner=0 --group=0 --numeric-owner -cf - | gzip -n -9 \
  >/out/clamav-$version-portable-musl-linux-amd64.tar.gz
cd /out && sha256sum clamav-$version-portable-musl-linux-amd64.tar.gz >SHA256SUMS

#!/bin/sh
# Rebuild toa.bpf.o from toa.bpf.c and refresh SHA256SUMS (run on Linux):
#   docker run --rm --platform linux/arm64 -v "$PWD":/bpf debian:13 sh /bpf/build.sh
# The object only uses UAPI context structs (no vmlinux.h, no CO-RE
# relocations), so one little-endian object serves amd64 and arm64. The
# output is reproducible: clang 19 (Debian 13) gives the hash in SHA256SUMS.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
if ! command -v clang >/dev/null 2>&1; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq >/dev/null
	apt-get install -y -qq --no-install-recommends clang llvm libbpf-dev linux-libc-dev >/dev/null
fi
arch_inc=/usr/include/$(uname -m)-linux-gnu
clang -O2 -g -target bpfel -I"$arch_inc" \
	-fdebug-prefix-map="$here"=. -fno-ident \
	-c "$here/toa.bpf.c" -o "$here/toa.bpf.o.tmp"
# Keep BTF (needed by the sk_storage map); drop DWARF so the object is small
# and independent of the build path.
llvm-strip -g "$here/toa.bpf.o.tmp"
mv "$here/toa.bpf.o.tmp" "$here/toa.bpf.o"
cd "$here" && sha256sum toa.bpf.c toa.bpf.o > SHA256SUMS
cat SHA256SUMS

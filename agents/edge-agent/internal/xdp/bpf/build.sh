#!/bin/sh
# Rebuild xdp.bpf.o from xdp.bpf.c and refresh SHA256SUMS (run on Linux):
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
	-c "$here/xdp.bpf.c" -o "$here/xdp.bpf.o.tmp"
# Keep BTF (cilium/ebpf reads the map definitions from it); drop DWARF so the object is small
# and independent of the build path.
llvm-strip -g "$here/xdp.bpf.o.tmp"
mv "$here/xdp.bpf.o.tmp" "$here/xdp.bpf.o"
cd "$here" && sha256sum xdp.bpf.c xdp.bpf.o > SHA256SUMS
cat SHA256SUMS

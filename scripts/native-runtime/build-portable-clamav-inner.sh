#!/bin/bash
# Runs inside the pinned Debian builder; see build-portable-clamav.sh.
set -euo pipefail
version=1.4.6
release=https://github.com/Cisco-Talos/clamav/releases/download/clamav-$version
rpm_sha256=746feb3d9f1c2273c38fd9ac3129b2eafa358078870fef3d76afebf9a4bdd4ae
license_sha256=0c4fd2fa9733fc9122503797648710851e4ee6d9e4969dd33fcbd8c63cd2f584
prefix=cdnca-clamav-1.4
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends ca-certificates curl patchelf binutils file python3 >/dev/null
cd /tmp
for attempt in 1 2 3 4 5; do curl -fsSL -o clamav.rpm "$release/clamav-$version.linux.x86_64.rpm" && break; sleep 3; done
echo "$rpm_sha256  clamav.rpm" | sha256sum -c -
curl -fsSL -o COPYING.txt "https://raw.githubusercontent.com/Cisco-Talos/clamav/clamav-$version/COPYING.txt"
echo "$license_sha256  COPYING.txt" | sha256sum -c -
# RPM lead + signature header (8-byte aligned) + main header, then an xz newc cpio.
python3 - clamav.rpm extract <<'PY'
import lzma, os, stat, struct, sys
data = open(sys.argv[1], "rb").read()
def header(offset):
    assert data[offset:offset + 3] == b"\x8e\xad\xe8"
    count, size = struct.unpack(">II", data[offset + 8:offset + 16])
    return offset + 16 + count * 16 + size
offset = (header(96) + 7) & ~7
raw = lzma.decompress(data[header(offset):])
position = 0
while True:
    assert raw[position:position + 6] == b"070701"
    fields = [int(raw[position + 6 + 8 * i:position + 14 + 8 * i], 16) for i in range(13)]
    mode, size, name_size = fields[1], fields[6], fields[11]
    name = raw[position + 110:position + 109 + name_size].decode()
    position = (position + 110 + name_size + 3) & ~3
    body = raw[position:position + size]
    position = (position + size + 3) & ~3
    if name == "TRAILER!!!":
        break
    path = os.path.normpath(os.path.join(sys.argv[2], name.lstrip("./")))
    assert path.startswith(sys.argv[2] + "/")
    if stat.S_ISDIR(mode):
        os.makedirs(path, exist_ok=True)
    elif stat.S_ISLNK(mode):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(body.decode(), path)
    elif stat.S_ISREG(mode):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as output:
            output.write(body)
        os.chmod(path, stat.S_IMODE(mode))
PY
source=extract/usr/local
root=/tmp/stage/$prefix
mkdir -p "$root/bin" "$root/sbin" "$root/lib64" "$root/share/doc"
cp -a "$source/sbin/clamd" "$root/sbin/"
cp -a "$source/bin/freshclam" "$source/bin/clamdscan" "$source/bin/clamscan" "$source/bin/clamconf" "$root/bin/"
cp -a "$source"/lib64/*.so* "$root/lib64/"
# DT_RPATH (not RUNPATH) so the libraries' own dependencies resolve the same way.
find "$root" -type f | while read -r path; do
  if file -b "$path" | grep -q ELF; then patchelf --force-rpath --set-rpath "\$ORIGIN/../lib64" "$path"; fi
done
find "$root/lib64" -type f -name '*.so*' -exec patchelf --force-rpath --set-rpath '$ORIGIN' {} +
LD_LIBRARY_PATH= "$root/bin/clamscan" --version
ldd "$root/sbin/clamd" "$root/bin/freshclam" | grep -E "clam|not found"
find "$root" -type f | while read -r path; do
  if file -b "$path" | grep -q ELF; then objdump -T "$path"; fi
done | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1 >/out/glibc-floor.txt
cp COPYING.txt "$root/share/doc/COPYING.txt"
printf 'ClamAV %s (GPL-2.0), repacked unmodified from %s/clamav-%s.linux.x86_64.rpm\n(sha256 %s): binaries and libraries moved under one prefix, RPATH set to $ORIGIN.\nCorresponding source: %s/clamav-%s.tar.gz\n' \
  "$version" "$release" "$version" "$rpm_sha256" "$release" "$version" >"$root/share/doc/SOURCE.txt"
find "$root" -exec touch -h -d 2026-10-16T00:00:00Z {} +
cd /tmp/stage
find "$prefix" -print0 | LC_ALL=C sort -z >/tmp/files
tar --null --no-recursion -T /tmp/files --owner=0 --group=0 --numeric-owner -cf - | gzip -n -9 \
  >/out/clamav-$version-portable-linux-amd64.tar.gz
cd /out && sha256sum clamav-$version-portable-linux-amd64.tar.gz >SHA256SUMS

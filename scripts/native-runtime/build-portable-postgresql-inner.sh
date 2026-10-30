#!/bin/bash
# Runs inside the pinned manylinux2014 (glibc 2.17) builder; see build-portable-postgresql.sh.
set -euo pipefail
source_url=https://ftp.postgresql.org/pub/source/v17.11/postgresql-17.11.tar.bz2
source_sha256=dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979
prefix=/opt/cdnca-postgresql-17
# vault.centos.org now answers 403; CENTOS_VAULT_MIRROR selects the archive mirror.
mirror=${CENTOS_VAULT_MIRROR:-https://mirrors.aliyun.com/centos-vault}
sed -i -e 's|^mirrorlist=|#mirrorlist=|' \
  -e "s|^#\\?baseurl=https\\?://vault.centos.org/centos/\\\$releasever|baseurl=$mirror/7.9.2009|" /etc/yum.repos.d/CentOS-Base.repo
yum -y -q --disablerepo='*' --enablerepo=base install flex file >/dev/null
cd /tmp
# The builder curl (7.29) has no --retry-all-errors; resume across short reads.
for attempt in 1 2 3 4 5; do curl -fsSL -C - -o postgresql.tar.bz2 "$source_url" && break; sleep 3; done
echo "$source_sha256  postgresql.tar.bz2" | sha256sum -c -
tar -xjf postgresql.tar.bz2
cd postgresql-17.11
# Same compiled-in socket directory as the Debian/RHEL packages: the default
# /tmp lets any local user pre-create the socket path, and psql/libpq without
# -h (install-control's runuser psql) would connect to it.
sed -i 's|^#define DEFAULT_PGSOCKET_DIR  "/tmp"$|#define DEFAULT_PGSOCKET_DIR "/run/postgresql"|' src/include/pg_config_manual.h
grep -qx '#define DEFAULT_PGSOCKET_DIR "/run/postgresql"' src/include/pg_config_manual.h
# $ORIGIN keeps libpq resolvable wherever the tree is unpacked; "$$" reaches the
# linker as a literal "$" through make.
./configure --prefix="$prefix" --without-icu --without-readline --without-openssl --with-zlib \
  LDFLAGS='-Wl,-rpath,$$ORIGIN/../lib' >/tmp/configure.log
make -j"$(nproc)" -s world-bin >/tmp/make.log 2>&1
make -s install-world-bin DESTDIR=/tmp/stage >/tmp/install.log 2>&1
root=/tmp/stage$prefix
find "$root/bin" "$root/lib" -type f \( -perm -u+x -o -name '*.so*' \) -exec strip --strip-unneeded {} + 2>/dev/null || true
rm -rf "$root/include" "$root/lib/pgxs" "$root/lib/pkgconfig" "$root/share/doc" "$root/share/man"
find "$root/lib" -name '*.a' -delete
"$root/bin/postgres" --version
# Highest glibc symbol version any ELF in the runtime needs (must be <= 2.17).
find "$root" -type f | while read -r path; do
  if file -b "$path" | grep -q ELF; then objdump -T "$path"; fi
done | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1 >/out/glibc-floor.txt
cd /tmp/stage/opt
find cdnca-postgresql-17 -print0 | LC_ALL=C sort -z >/tmp/files
tar --null --no-recursion -T /tmp/files --owner=0 --group=0 --numeric-owner --mtime=2026-10-16 -cf - | gzip -n -9 \
  >/out/postgresql-17.11-portable-linux-amd64.tar.gz
cd /out && sha256sum postgresql-17.11-portable-linux-amd64.tar.gz >SHA256SUMS

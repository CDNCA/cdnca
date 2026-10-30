#!/bin/sh
# Builds and runs the JA4 parser unit test (with ASan/UBSan where available).
#   OPENSSL_PREFIX  OpenSSL 3 prefix with include/ and lib/ (default: pkg-config,
#                   then Homebrew openssl@3)
set -eu
here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-ja4-test.XXXXXX")"
trap 'rm -rf -- "${work}"' EXIT INT TERM
if [ -n "${OPENSSL_PREFIX:-}" ]; then
  flags="-I${OPENSSL_PREFIX}/include -L${OPENSSL_PREFIX}/lib"
elif pkg-config --exists libcrypto 2>/dev/null; then
  flags="$(pkg-config --cflags --libs-only-L libcrypto)"
elif [ -d /opt/homebrew/opt/openssl@3 ]; then
  flags="-I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib"
else
  flags=""
fi
sanitize="-fsanitize=address,undefined -fno-omit-frame-pointer"
# shellcheck disable=SC2086
cc -std=c99 -O1 -g -Wall -Wextra -Werror ${sanitize} ${flags} -I"${here}" \
  "${here}/cdnca_ja4.c" "${here}/cdnca_ja4_test.c" -lcrypto -o "${work}/ja4-test"
"${work}/ja4-test"

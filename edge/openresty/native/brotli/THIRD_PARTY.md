# ngx_brotli (vendored)

`filter/ngx_http_brotli_filter_module.c` and `LICENSE` are byte for byte
google/ngx_brotli at commit `a71f9312c2deb28875acc7bacfdd5695a111aa53`
(2023-10-09, the latest upstream commit when vendored on 2026-10-21). Upstream
hashes (sha256): module `af1a9fc7cd308ee7c1752d0aa64cec5c0a76f40fe2dec3e87ba60c9c4c9154b1`,
LICENSE `d77d1c7a59ab34c2b031299b9b606d27b3ceacad5c817a69444a94ccb6943454`.

License: BSD 2-Clause style (Copyright Igor Sysoev, Nginx, Inc., Google Inc.;
see LICENSE). Not MIT, but equally permissive; redistribution keeps the notice.

`config` is CDNCA's: the filter module only, linked against the system Brotli
(Alpine `brotli-dev`, the same `brotli-libs` both runtime bases ship), instead
of upstream's `deps/brotli` submodule. Step 26 of the source chain then lets
`brotli_comp_level` take variables (per-site level on a shared `server{}`).

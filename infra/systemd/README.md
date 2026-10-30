# systemd packaging skeleton

`cdnca-openresty.service` runs the active immutable release as the dedicated
`cdnca-edge` user. The package installer must create that system user and
install OpenResty at `/usr/local/openresty/bin/openresty` before enabling the
unit. The edge Agent owns release staging, the `current` symlink, precheck,
activation, health confirmation, and rollback; systemd owns only process
lifecycle.

The service grants only `CAP_NET_BIND_SERVICE`, keeps `/usr`, `/etc`, the
`current` link, and immutable releases read-only in its mount namespace. Only
`/var/lib/cdnca-edge/shared` is writable by OpenResty for its PID, logs, and
temporary files. LuaJIT needs executable memory, so `MemoryDenyWriteExecute`
must not be enabled without a tested non-JIT build.

Stage the packaging files without writing to the host root:

```sh
./scripts/edge-runtime-install.sh --destdir /tmp/cdnca-edge-package-root
```

The staging script intentionally refuses `/` as `--destdir`. Native package
post-install scripts must separately create the `cdnca-edge` system user, run
`systemd-tmpfiles`, install the signed Agent and OpenResty artifacts, and only
then enable services. `scripts/edge-runtime-linux-smoke.sh` performs the
isolated Debian 12 and Ubuntu 24.04 install and systemd lifecycle test. Native
package upgrade and rollback tests remain a separate release gate.

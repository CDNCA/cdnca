lua-resty-ipmatcher (Apache-2.0), api7/lua-resty-ipmatcher commit
62d4c44d67227e8f3fe02331c2f8b90fe0d7ccd1, `resty/ipmatcher.lua` sha256
1c40f52bed3f85964bfa4c2ff686d11ed12643c08caf0addfb74e3996bf6bd0a — the same
pin the container image downloads (edge/openresty/Dockerfile IPMATCHER_*).
The native node image builds offline from the checkout, so the file is
vendored here; edge/openresty/native/Dockerfile copies it into
lualib/resty/ (the firewall action engine requires "resty.ipmatcher").

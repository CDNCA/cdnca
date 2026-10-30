#!/bin/sh
set -eu

state_root="${CDNCA_EDGE_STATE_ROOT:-/var/lib/cdnca-edge}"
case "${state_root}" in
  /*) ;;
  *)
    echo "CDNCA_EDGE_STATE_ROOT must be an absolute path" >&2
    exit 78
    ;;
esac
case "/${state_root#/}/" in
  */../*|*/./*)
    echo "CDNCA_EDGE_STATE_ROOT must be a clean path" >&2
    exit 78
    ;;
esac

current="${state_root}/current"
if [ ! -L "${current}" ]; then
  echo "active release symlink is missing: ${current}" >&2
  exit 78
fi

release="$(readlink -f "${current}")"
case "${release}" in
  "${state_root}"/releases/*) ;;
  *)
    echo "active release resolves outside the release store" >&2
    exit 78
    ;;
esac
if [ ! -f "${release}/nginx.conf" ]; then
  echo "active release has no nginx.conf" >&2
  exit 78
fi

mkdir -p "${state_root}/shared"
ready_file="${CDNCA_SECURITY_RUNTIME_READY_FILE:-/var/run/cdnca/security-runtime.ready}"
case "${ready_file}" in
  /*) ;;
  *)
    echo "CDNCA_SECURITY_RUNTIME_READY_FILE must be an absolute path" >&2
    exit 78
    ;;
esac
rm -f "${ready_file}"
range_sha256="d528c1309c2bfa0c9c48348185c1966d8a764a67164099cf6a522955667f7fdc"
waf_sha256="92f3fd132d9a526afaf0264fc537969e6e28498654abc39f908a2e88472ab7f7"
cc_sha256="858e87fffc8c8e246cf50ead9e272f673a97f682031a7e012a533722e3f5dbfd"
adaptive_sha256="38314497958285c1072e4e1ef7d4c0fbe41e3e03ed148807a008a6cb88e4cb21"
urlauth_sha256="93405cdcf5e2a7edef1198cc3e09c6f1584cca6bd351e8561cb1c96c0aaa0bcc"
challenge_engine_sha256="a6dbe6c1bc19e5732802d2c4e5ea0c9670752a01b57ac0ddd52c93b67d440f31"
challenge_crypto_sha256="f3198f31e12cb5700d78a80ca4f038e97db949e847f3e8d27e228b4263dc0367"
challenge_ip_sha256="02372567c92ceea47959291959b2381e13836a2011a4819c52805f8f57324631"
httppolicy_sha256="4b9bb65918b71c73b079e008a1c51af84000e3b431f361a0ea49009216090f47"
firewallaction_sha256="111498e20ea67dcf063ce61099367c0f914646776ab12f2df9843e3006896468"
siteaccess_sha256="d1d4089ff06a88f39f298556cc7acac33ed9a4b1a9295788201ba804bbeaaeaf"
l4geo_engine_sha256="23060482e83ed151be91e08ca39348ec9d66423143a380e2ffd6afeca6a2ce91"
l4geo_shim_sha256="2eca890fb7c2845541cba744cf76b9a2ad880068e3e2f1961377f32ffaa19dad"
errorpage_sha256="9925161ff580e70b28ea54139c163a1ee309d4e9baff42c5a008323022a88555"
originauth_engine_sha256="4a5bd07cdd59f794e623ad439155db118e6998caf3e044bb7d42a668b279f540"
originauth_crypto_sha256="412001acc02f72f0cc5fe66216dfe58149776452e46a6fe3140b8dcc421d0b4f"
iplib_sha256="a50bfda12abcfac7906c405bd8d7eaf81010c29c840ddce2a4459ce453cebe83"
rule_interp_sha256="f319da5a0c9ea6cfb977261a8ddca63f57530336d28851dc5fcf80715f1dedb0"
banlist_sha256="ea49f5bfa9b7945d5af8f521ae4cecd95cca7ef0ea89363afe2e8c5b077e4e8f"
dynroute_sha256="8b6fdc87b5f6114e695a175ddeb3743ea3a33e1928ec8cdf965d6c3eb9076e67"
dynroute_telemetry_sha256="911e19af52ff52dd71649817ab020fe293b17154b9fd1ec9928a8016dc1a2156"
dynroute_webp_sha256="8bb4d8252e1d9179024902e3e0718c17f5389306162e0494908fcee7738019ba"
dynroute_webp_codec_sha256="f25d44de9cb6919c7b8928df2a6b25df9c898884648ea3395b5959000351f481"
dynroute_site_sha256="5011685413909ce4b8b2ff010e3d505378d3c9ac6797218afc16118c80b990c0"
dynroute_origin_sha256="95b2185b927cdf68e8d83287080d678fafb93f90509899d1276827078684fe58"
dynroute_origintls_sha256="9c11911356ffe8f11b73c8b4b145ce615094f015543fbed74687cab90cfdbbf2"
dynroute_cache_sha256="b40f1d01e84ef66c3c89eba411a8af181643f68112d615b5c8c35c3683efd460"
dynroute_security_sha256="04adf8a5105fbeb1741c366cb139ee79907e8c0e527b4726054904d41606e71e"
dynroute_managed_waf_sha256="8526a9029ec4f0438dd4823cb1ac427ec6c5155d2a73927ec38e902522de0d91"
dynroute_rule_plan_sha256="88fa2f83ad725ec7facb984ddd6a58ce3e4c3138d29b37fe76b9e60a2a3412cb"
dynroute_bot_sha256="780a3da89e488a77dce21096b6640bb7ac0ebf67bd6675b79519442ad3f83cc6"
dynroute_filters_sha256="540096964f040319c36d3ac41e1ac86121c762e6028fbffee3ec3562aafc26e0"
dynroute_limits_sha256="7442c3f1803bf8d013eb57c436b76e84a01e6a911f3a54b75fce1b1770baf471"
dynroute_originauth_sha256="3df863a8177361103a0deb58cc1a8291f636f5a85c9d4d47f5613dde4f7171f8"
dynroute_site_admin_sha256="beba3171b3e53abacc031fe7c73dd7da081dc3e3e4276f1a3034972cd723cebe"
dynroute_tls_sha256="66bc1559487b74f24cc5219df766ed46987e19785feb9b6cb4eeb8a8250c686f"
sched302_sha256="d5da71ac193e8d904b4aa447bde442bd0ffd3ff316b89ec8908657fb5ed9712e"
printf '%s  %s\n' "${range_sha256}" /usr/local/share/cdnca/range/guard.lua | sha256sum -c -
printf '%s  %s\n' "${waf_sha256}" /usr/local/share/cdnca/security/cdnca_waf.lua | sha256sum -c -
printf '%s  %s\n' "${rule_interp_sha256}" /usr/local/share/cdnca/security/cdnca_rule_interp.lua | sha256sum -c -
printf '%s  %s\n' "${banlist_sha256}" /usr/local/share/cdnca/security/cdnca_banlist.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_site_sha256}" /usr/local/share/cdnca/dynroute/cdnca_site.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_site_admin_sha256}" /usr/local/share/cdnca/dynroute/cdnca_site_admin.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_tls_sha256}" /usr/local/share/cdnca/dynroute/cdnca_tls.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_origin_sha256}" /usr/local/share/cdnca/dynroute/cdnca_origin.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_originauth_sha256}" /usr/local/share/cdnca/dynroute/cdnca_originauth.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_origintls_sha256}" /usr/local/share/cdnca/dynroute/cdnca_origintls.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_cache_sha256}" /usr/local/share/cdnca/dynroute/cdnca_cache.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_security_sha256}" /usr/local/share/cdnca/dynroute/cdnca_security.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_managed_waf_sha256}" /usr/local/share/cdnca/dynroute/cdnca_managed_waf.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_rule_plan_sha256}" /usr/local/share/cdnca/dynroute/cdnca_rule_plan.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_bot_sha256}" /usr/local/share/cdnca/dynroute/cdnca_bot.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_filters_sha256}" /usr/local/share/cdnca/dynroute/cdnca_filters.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_limits_sha256}" /usr/local/share/cdnca/dynroute/cdnca_limits.lua | sha256sum -c -
printf '%s  %s\n' "${cc_sha256}" /usr/local/share/cdnca/security/cc.lua | sha256sum -c -
printf '%s  %s\n' "${adaptive_sha256}" /usr/local/share/cdnca/security/cc_adaptive.lua | sha256sum -c -
printf '%s  %s\n' "${urlauth_sha256}" /usr/local/share/cdnca/security/url_auth.lua | sha256sum -c -
printf '%s  %s\n' "${challenge_engine_sha256}" /usr/local/share/cdnca/challenge/engine.lua | sha256sum -c -
printf '%s  %s\n' "${challenge_crypto_sha256}" /usr/local/share/cdnca/challenge/crypto.lua | sha256sum -c -
printf '%s  %s\n' "${challenge_ip_sha256}" /usr/local/share/cdnca/challenge/ip.lua | sha256sum -c -
printf '%s  %s\n' "${httppolicy_sha256}" /usr/local/share/cdnca/httppolicy/engine.lua | sha256sum -c -
printf '%s  %s\n' "${firewallaction_sha256}" /usr/local/share/cdnca/firewallaction/engine.lua | sha256sum -c -
printf '%s  %s\n' "${siteaccess_sha256}" /usr/local/share/cdnca/siteaccess/engine.lua | sha256sum -c -
printf '%s  %s\n' "${l4geo_engine_sha256}" /opt/cdnca/l4geo/engine.lua | sha256sum -c -
printf '%s  %s\n' "${l4geo_shim_sha256}" /opt/cdnca/l4geo/cdnca_l4_geo.lua | sha256sum -c -
printf '%s  %s\n' "${errorpage_sha256}" /usr/local/share/cdnca/errorpage/handler.lua | sha256sum -c -
printf '%s  %s\n' "${originauth_engine_sha256}" /usr/local/share/cdnca/originauth/engine.lua | sha256sum -c -
printf '%s  %s\n' "${originauth_crypto_sha256}" /usr/local/share/cdnca/originauth/crypto.lua | sha256sum -c -
printf '%s  %s\n' "${iplib_sha256}" /usr/local/share/cdnca/security/cdnca_iplib.lua | sha256sum -c -
printf '%s  %s\n' "${iplib_sha256}" /opt/cdnca/l4geo/cdnca_iplib.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_sha256}" /usr/local/share/cdnca/dynroute/cdnca_dynroute.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_telemetry_sha256}" /usr/local/share/cdnca/dynroute/cdnca_telemetry.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_webp_sha256}" /usr/local/share/cdnca/dynroute/cdnca_webp.lua | sha256sum -c -
printf '%s  %s\n' "${dynroute_webp_codec_sha256}" /usr/local/share/cdnca/dynroute/cdnca_webp_codec.lua | sha256sum -c -
printf '%s  %s\n' "${sched302_sha256}" /usr/local/share/cdnca/sched302/cdnca_sched302.lua | sha256sum -c -
/usr/local/openresty/bin/resty -e 'package.path = "/usr/local/share/cdnca/?.lua;" .. package.path; local range_guard = require("range.guard"); assert(type(range_guard.access) == "function"); assert(type(range_guard.header_filter) == "function"); assert(type(range_guard.body_filter) == "function"); assert(loadfile("/usr/local/share/cdnca/security/cdnca_waf.lua")); assert(loadfile("/usr/local/share/cdnca/security/cc.lua")); assert(loadfile("/usr/local/share/cdnca/security/cc_adaptive.lua")); package.path = "/usr/local/share/cdnca/security/?.lua;" .. package.path; local url_auth = require("url_auth"); assert(type(url_auth.init) == "function"); assert(type(url_auth.init_worker) == "function"); assert(type(url_auth.access) == "function"); package.path = "/usr/local/share/cdnca/challenge/?.lua;" .. package.path; local challenge = require("engine"); assert(type(challenge.init) == "function"); assert(type(challenge.access) == "function"); assert(type(require("crypto")) == "table"); assert(type(require("ip")) == "table")'
/usr/local/openresty/bin/openresty -t -p "${current}/" -c nginx.conf
config_sha256="$(sha256sum "${release}/nginx.conf" | awk '{print $1}')"
mkdir -p "$(dirname "${ready_file}")"
ready_tmp="${ready_file}.$$"
printf '{"schema_version":"cdnca.security-runtime-ready/v1","waf_sha256":"%s","cc_sha256":"%s","adaptive_sha256":"%s","config_sha256":"%s","cc_api_version":2}\n' \
  "${waf_sha256}" "${cc_sha256}" "${adaptive_sha256}" "${config_sha256}" >"${ready_tmp}"
chmod 0444 "${ready_tmp}"
mv -f "${ready_tmp}" "${ready_file}"
exec /usr/local/openresty/bin/openresty -g "daemon off;" -p "${current}/" -c nginx.conf

#!/bin/sh
# waf-apptype: real OpenResty acceptance of CRS application types (OWASP CRS
# official application exclusion plugins as system/app-* packs). One --rm
# --network none container of the node runtime image with the ModSecurity
# engine extension mounted; cdnca-waf-apptype-check renders the site runtime 8
# managed WAF exactly as a node does and checks:
#   - a site with application type WordPress: the plugin's own regression
#     requests (wp-login, setup-config, install) pass; CRS PL1 blocks them
#     on a site of the same node without it and on a node without any
#     application pack (not selected = behaviour unchanged);
#   - attacks the exclusions do not cover are blocked on every site;
#   - only the WordPress site's transactions carry the app marker.
#   APPTYPE_IMAGE        node runtime image (default cdnca-native-runtime:edge-golden)
#   MODSECURITY_RUNTIME  engine extension (default scripts/security/modsecurity-runtime.sh)
#   APPTYPE_WRAP         command prefix for docker (the shared machine's job queue)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${APPTYPE_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
runtime=${MODSECURITY_RUNTIME:-$(sh "${repo_root}/scripts/security/modsecurity-runtime.sh")}
[ -f "${runtime}/modules/ngx_http_modsecurity_module.so" ] || { echo "BLOCKED: no ModSecurity runtime at ${runtime}" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-apptype.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/wafengine/cmd/cdnca-waf-apptype-check
mkdir -p "${work}/packs"
cp -R "${repo_root}/libs/rulepack/testdata/crs-profiles" "${repo_root}/libs/rulepack/testdata/crs-apps" "${work}/packs/"
cp "${repo_root}/libs/entitlement/rulecatalog/crs/rules.json" "${work}/rules.json"
chmod -R a+rX "${work}"
# The module finds libmodsecurity under its build prefix: mount it there.
${APPTYPE_WRAP:-} docker run --rm --init --network none -v "${work}:/check:ro" \
	-v "${runtime}:/usr/local/openresty/modsecurity:ro" --entrypoint /check/check "${image}" \
	-packs /check/packs -crs /check/rules.json -state /tmp/apptype

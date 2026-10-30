#!/bin/sh

set -eu

if [ "$#" -ne 0 ]; then
	echo config_rejected >&2
	exit 2
fi

if [ "${CDNCA_DNS_LIVE_MUTATION_ACK-}" != "dedicated-disposable-zone" ]; then
	echo config_rejected >&2
	exit 2
fi

enabled_count=0
selected_provider=

check_provider() {
	provider_name=$1
	enabled_value=$2
	present_marker=$3
	if [ "$present_marker" = x ] && [ "$enabled_value" != 0 ] && [ "$enabled_value" != 1 ]; then
		echo config_rejected >&2
		exit 2
	fi
	if [ "$enabled_value" = 1 ]; then
		enabled_count=$((enabled_count + 1))
		selected_provider=$provider_name
	fi
}

check_provider CLOUDFLARE "${CDNCA_DNS_LIVE_CLOUDFLARE_ENABLED-}" "${CDNCA_DNS_LIVE_CLOUDFLARE_ENABLED+x}"
check_provider ALIYUN "${CDNCA_DNS_LIVE_ALIYUN_ENABLED-}" "${CDNCA_DNS_LIVE_ALIYUN_ENABLED+x}"
check_provider HUAWEI "${CDNCA_DNS_LIVE_HUAWEI_ENABLED-}" "${CDNCA_DNS_LIVE_HUAWEI_ENABLED+x}"
check_provider DNSPOD_CN "${CDNCA_DNS_LIVE_DNSPOD_CN_ENABLED-}" "${CDNCA_DNS_LIVE_DNSPOD_CN_ENABLED+x}"
check_provider DNS_COM "${CDNCA_DNS_LIVE_DNS_COM_ENABLED-}" "${CDNCA_DNS_LIVE_DNS_COM_ENABLED+x}"
check_provider DNS_LA "${CDNCA_DNS_LIVE_DNS_LA_ENABLED-}" "${CDNCA_DNS_LIVE_DNS_LA_ENABLED+x}"

if [ "$enabled_count" -ne 1 ] || [ -z "$selected_provider" ]; then
	echo config_rejected >&2
	exit 2
fi

case "$selected_provider" in
	CLOUDFLARE)
		service=${CDNCA_DNS_LIVE_CLOUDFLARE_KEYCHAIN_SERVICE-}
		account=${CDNCA_DNS_LIVE_CLOUDFLARE_KEYCHAIN_ACCOUNT-}
		;;
	ALIYUN)
		service=${CDNCA_DNS_LIVE_ALIYUN_KEYCHAIN_SERVICE-}
		account=${CDNCA_DNS_LIVE_ALIYUN_KEYCHAIN_ACCOUNT-}
		;;
	HUAWEI)
		service=${CDNCA_DNS_LIVE_HUAWEI_KEYCHAIN_SERVICE-}
		account=${CDNCA_DNS_LIVE_HUAWEI_KEYCHAIN_ACCOUNT-}
		;;
	DNSPOD_CN)
		service=${CDNCA_DNS_LIVE_DNSPOD_CN_KEYCHAIN_SERVICE-}
		account=${CDNCA_DNS_LIVE_DNSPOD_CN_KEYCHAIN_ACCOUNT-}
		;;
	DNS_COM)
		service=${CDNCA_DNS_LIVE_DNS_COM_KEYCHAIN_SERVICE-}
		account=${CDNCA_DNS_LIVE_DNS_COM_KEYCHAIN_ACCOUNT-}
		;;
	DNS_LA)
		service=${CDNCA_DNS_LIVE_DNS_LA_KEYCHAIN_SERVICE-}
		account=${CDNCA_DNS_LIVE_DNS_LA_KEYCHAIN_ACCOUNT-}
		;;
esac

if [ -z "$service" ] || [ -z "$account" ]; then
	echo config_rejected >&2
	exit 2
fi
unset service account selected_provider enabled_value present_marker provider_name

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(dirname -- "$script_directory")
cd "$repository_root/services/control-api"
exec go run ./cmd/dns-provider-propagation-live

#!/bin/sh
# Node cache purge scale benchmark: the agent's zone-scan purges
# (dyncache Zones.Purge / PurgeSite / UsageBySite) over synthetic nginx
# cache files, one loop-mounted ext4 image per dataset on a Docker volume
# (Linux page cache, O_NOATIME; cold = unmount + mount).
# Source: agents/edge-agent/internal/dyncache/scale_test.go (-tags scale) and
# the purge index scenarios, scale_index_test.go:
# ibuild, isync, idir10, idir1, iwild10, iwild1, iwildexact, iexactscan, isite.
#
#   tests/scale/cache-purge/run.sh build
#   tests/scale/cache-purge/run.sh gen   <dataset> <target> <other> [body]
#   tests/scale/cache-purge/run.sh run   <dataset> <scenario> cold|hot
#   tests/scale/cache-purge/run.sh clean
#
# Results: SCALE_RESULT JSON lines appended to $OUT/results.jsonl.
set -eu
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
out=${OUT:-/tmp/purge-scale}
volume=${VOLUME:-cdnca-purge-scale}
box=${BOX:-cdnca-purge-scale}
arch=$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/; s/x86_64/amd64/')
mkdir -p "${out}"

start() {
	docker container inspect "${box}" >/dev/null 2>&1 && return
	docker volume create "${volume}" >/dev/null
	# privileged: loop mounts; 4 CPUs (the walk is serial) and 2 GiB (page
	# cache included) so the shared Docker Desktop VM keeps its memory
	docker run -d --name "${box}" --privileged --cpus 4 --memory "${MEMORY:-2g}" -v "${volume}:/data" -v "${out}:/out:ro" \
		debian:bookworm-slim sleep infinity >/dev/null
}
in_box() { docker exec "$@"; }

# Every dataset is its own ext4 image on the volume, loop-mounted at
# /data/<dataset>. A cold run unmounts it (its page, inode and dentry cache
# go with the file system and the auto-cleared loop device), drops the
# image file's pages from the VM page cache (POSIX_FADV_DONTNEED through dd
# iflag=nocache) and mounts it again. drop_caches is not used: on the shared
# Docker Desktop VM it did not finish while other containers kept creating
# inodes, and it would evict their caches too.
mount_dataset() { # dataset [size]
	in_box "${box}" sh -c "
		set -e
		mountpoint -q /data/$1 && exit 0
		mkdir -p /data/$1 /data/images
		if [ ! -f /data/images/$1.img ]; then
			truncate -s ${2:-24G} /data/images/$1.img
			mkfs.ext4 -q -F -i 4096 -E lazy_itable_init=0,lazy_journal_init=0 /data/images/$1.img
		fi
		mount -o loop,noatime /data/images/$1.img /data/$1"
}

case "${1:-}" in
build)
	GOOS=linux GOARCH=${arch} CGO_ENABLED=0 go -C "${repo_root}/agents/edge-agent" test -c -tags scale \
		-o "${out}/dyncache.test" ./internal/dyncache
	;;
gen)
	start
	mount_dataset "$2" "${SIZE:-24G}"
	in_box -e SCALE_ROOT="/data/$2" -e SCALE_TARGET="$3" -e SCALE_OTHER="$4" -e SCALE_BODY="${5:-1024}" "${box}" \
		nice /out/dyncache.test -test.run '^TestScaleGenerate$' -test.v -test.timeout 3h | grep -E 'generated|FAIL|ok'
	in_box "${box}" sh -c "sync; df -h /data/$2 | tail -1; df -i /data/$2 | tail -1"
	;;
run)
	start
	dataset=$2 scenario=$3 mode=$4
	mount_dataset "${dataset}"
	case "${scenario}" in ibuild | isync) ;; i*)
		# the index purges start from a synced index: the catch-up after the
		# previous run's repair is recorded apart (label <dataset>/catchup)
		in_box -e SCALE_ROOT="/data/${dataset}" -e SCALE_SCENARIO=isync -e SCALE_LABEL="${dataset}/catchup" "${box}" \
			nice /out/dyncache.test -test.run '^TestScaleRun$' -test.timeout 3h | grep '^SCALE_RESULT' |
			sed 's/^SCALE_RESULT //' >>"${out}/${RESULTS:-results}.jsonl"
		;;
	esac
	if [ "${mode}" = cold ]; then
		in_box "${box}" sh -c "sync; umount /data/${dataset}; dd if=/data/images/${dataset}.img iflag=nocache count=0 status=none"
		mount_dataset "${dataset}"
	else
		in_box -e SCALE_ROOT="/data/${dataset}" -e SCALE_SCENARIO=usage "${box}" \
			nice /out/dyncache.test -test.run '^TestScaleRun$' -test.timeout 3h >/dev/null
	fi
	in_box -e SCALE_ROOT="/data/${dataset}" -e SCALE_SCENARIO="${scenario}" -e SCALE_LABEL="${dataset}/${mode}" \
		-e SCALE_DEADLINE="${DEADLINE:-3600}" "${box}" \
		nice /out/dyncache.test -test.run '^TestScaleRun$' -test.timeout 3h | grep '^SCALE_RESULT' |
		sed "s/^SCALE_RESULT {/{\"host_load\":\"$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}')\",\"containers\":$(docker ps -q | wc -l | tr -d ' '),\"psi\":\"$(in_box "${box}" sh -c 'for r in cpu memory io; do printf "%s=%s " $r $(head -1 /proc/pressure/$r | cut -d" " -f3 | cut -d= -f2); done')\",/" |
		tee -a "${out}/${RESULTS:-results}.jsonl"
	case "${scenario}" in usage | ibuild | isync) ;; *)
		in_box -e SCALE_ROOT="/data/${dataset}" -e SCALE_SCENARIO="${scenario}" "${box}" \
			nice /out/dyncache.test -test.run '^TestScaleRepair$' -test.timeout 3h >/dev/null
		;;
	esac
	;;
clean)
	docker rm -f "${box}" >/dev/null 2>&1 || true
	docker volume rm "${volume}" >/dev/null 2>&1 || true
	;;
*)
	sed -n '2,15p' "$0"
	exit 2
	;;
esac

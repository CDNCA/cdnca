#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *)
    echo "unsupported Docker architecture: ${docker_arch}" >&2
    exit 69
    ;;
esac

tmp_base="${TMPDIR:-/tmp}"
test_run="${CDNCA_CACHE_TASK_TEST_RUN:-^(TestSmokeProcessGroupPidfdsCollectsRealLinuxWorker|TestStopSmokeRuntimeCleansRealLinuxWorkerAfterCommandLeaderExit|TestStopSmokeRuntimeRetriesRealLinuxDescendantCloseFailure|TestOpenRestyCacheTaskSmoke)$}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-cache-task.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-cache-task\.//')"
container="cdnca-edge-cache-task-${suffix}"
image="cdnca/openresty-runtime:cache-task-smoke-${suffix}"
task_owner="edge-cache-task-${suffix}"
container_label_key="cdnca.smoke.owner"
image_label_key="org.opencontainers.image.revision"
container_id=""
image_id=""
cleanup_failed=0

inspect_container() {
	inspect_output=""
	if inspect_output="$(docker inspect --type container "${1}" 2>&1)"; then
		return 0
	fi
	case "${inspect_output}" in
		*"No such object:"*|*"No such container:"*) return 1 ;;
		*)
			echo "inspect container failed: ${inspect_output}" >&2
			return 2
			;;
	esac
}

inspect_image() {
	inspect_output=""
	if inspect_output="$(docker image inspect "${1}" 2>&1)"; then
		return 0
	fi
	case "${inspect_output}" in
		*"No such object:"*|*"No such image:"*) return 1 ;;
		*)
			echo "inspect image failed: ${inspect_output}" >&2
			return 2
			;;
	esac
}

cleanup() {
	status="${1:-0}"
	trap - EXIT HUP INT TERM
	cleanup_failed=0
	if [ -n "${container_id}" ]; then
		if inspect_container "${container_id}"; then
			if owner="$(docker inspect --type container --format "{{ index .Config.Labels \"${container_label_key}\" }}" "${container_id}" 2>&1)"; then
				if [ "${owner}" != "${task_owner}" ]; then
					echo "refusing to remove container with changed owner" >&2
					cleanup_failed=1
				elif ! docker rm -f "${container_id}" >/dev/null; then
					echo "remove owned container failed" >&2
					cleanup_failed=1
				fi
			else
				echo "inspect owned container label failed: ${owner}" >&2
				cleanup_failed=1
			fi
		else
			inspect_status=$?
			if [ "${inspect_status}" -eq 1 ]; then
				if inspect_container "${container}"; then
					echo "refusing to remove replacement container" >&2
					cleanup_failed=1
				else
					inspect_status=$?
					if [ "${inspect_status}" -ne 1 ]; then
						cleanup_failed=1
					fi
				fi
			else
				cleanup_failed=1
			fi
		fi
	fi
	if inspect_container "${container}"; then
		if owner="$(docker inspect --type container --format "{{ index .Config.Labels \"${container_label_key}\" }}" "${container}" 2>&1)"; then
			if [ "${owner}" != "${task_owner}" ]; then
				echo "refusing to remove stable-name container with changed owner" >&2
				cleanup_failed=1
			elif ! docker rm -f "${container}" >/dev/null; then
				echo "remove stable-name owned container failed" >&2
				cleanup_failed=1
			fi
		else
			echo "inspect stable-name container label failed: ${owner}" >&2
			cleanup_failed=1
		fi
	else
		inspect_status=$?
		if [ "${inspect_status}" -ne 1 ]; then
			cleanup_failed=1
		fi
	fi
	if [ -n "${image_id}" ]; then
		if inspect_image "${image_id}"; then
			if owner="$(docker image inspect --format "{{ index .Config.Labels \"${image_label_key}\" }}" "${image_id}" 2>&1)"; then
				if [ "${owner}" != "${task_owner}" ]; then
					echo "refusing to remove image with changed owner" >&2
					cleanup_failed=1
				elif ! docker image rm "${image_id}" >/dev/null; then
					echo "remove owned image failed" >&2
					cleanup_failed=1
				fi
			else
				echo "inspect owned image label failed: ${owner}" >&2
				cleanup_failed=1
			fi
		else
			inspect_status=$?
			if [ "${inspect_status}" -eq 1 ]; then
				if inspect_image "${image}"; then
					echo "refusing to remove replacement image" >&2
					cleanup_failed=1
				else
					inspect_status=$?
					if [ "${inspect_status}" -ne 1 ]; then
						cleanup_failed=1
					fi
				fi
			else
				cleanup_failed=1
			fi
		fi
	fi
	if inspect_image "${image}"; then
		if owner="$(docker image inspect --format "{{ index .Config.Labels \"${image_label_key}\" }}" "${image}" 2>&1)"; then
			if [ "${owner}" != "${task_owner}" ]; then
				echo "refusing to remove stable-tag image with changed owner" >&2
				cleanup_failed=1
			elif ! docker image rm "${image}" >/dev/null; then
				echo "remove stable-tag owned image failed" >&2
				cleanup_failed=1
			fi
		else
			echo "inspect stable-tag image label failed: ${owner}" >&2
			cleanup_failed=1
		fi
	else
		inspect_status=$?
		if [ "${inspect_status}" -ne 1 ]; then
			cleanup_failed=1
		fi
	fi
	case "${workdir}" in
		"${tmp_base%/}"/cdnca-edge-cache-task.*)
			if [ -e "${workdir}" ] && { ! chmod -R u+w "${workdir}" 2>/dev/null || ! rm -rf -- "${workdir}"; }; then
				echo "remove owned work directory failed" >&2
				cleanup_failed=1
			fi
			;;
		*)
			echo "refusing to remove unexpected path: ${workdir}" >&2
			cleanup_failed=1
			;;
	esac
	if [ "${status}" -ne 0 ]; then
		exit "${status}"
	fi
	if [ "${cleanup_failed}" -ne 0 ]; then
		exit 1
	fi
}
trap 'cleanup "$?"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if inspect_container "${container}"; then
	echo "container name collision: ${container}" >&2
	exit 73
else
	inspect_status=$?
	if [ "${inspect_status}" -ne 1 ]; then
		exit 1
	fi
fi
if inspect_image "${image}"; then
	echo "image tag collision: ${image}" >&2
	exit 73
else
	inspect_status=$?
	if [ "${inspect_status}" -ne 1 ]; then
		exit 1
	fi
fi

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go test -c -trimpath -o "${workdir}/cachetask-smoke.test" ./internal/cachetask
)

if ! CDNCA_EDGE_REVISION="${task_owner}" "${repo_root}/scripts/edge-runtime-build.sh" "${image}" >"${workdir}/build.log" 2>&1; then
  sed -n '1,240p' "${workdir}/build.log" >&2
  exit 1
fi
if ! image_id="$(docker image inspect "${image}" --format '{{.Id}}' 2>&1)"; then
	echo "inspect built image id failed: ${image_id}" >&2
	exit 1
fi
if ! image_owner="$(docker image inspect "${image_id}" --format "{{ index .Config.Labels \"${image_label_key}\" }}" 2>&1)"; then
	echo "inspect built image owner failed: ${image_owner}" >&2
	exit 1
fi
if [ -z "${image_id}" ] || [ "${image_owner}" != "${task_owner}" ]; then
	echo "built image ownership mismatch" >&2
	exit 1
fi

container_id="$(docker run --detach \
	--name "${container}" \
	--label "${container_label_key}=${task_owner}" \
	--volume "${workdir}/cachetask-smoke.test:/usr/local/bin/cachetask-smoke.test:ro" \
  --volume "${repo_root}/edge/openresty/cache/cache-task-smoke.conf.tmpl:/fixtures/cache-task-smoke.conf.tmpl:ro" \
	--entrypoint /bin/sh \
	"${image}" \
	-c 'trap "exit 0" TERM INT; while :; do sleep 3600; done')"
if ! container_owner="$(docker inspect --type container --format "{{ index .Config.Labels \"${container_label_key}\" }}" "${container_id}" 2>&1)"; then
	echo "inspect created container owner failed: ${container_owner}" >&2
	exit 1
fi
if [ -z "${container_id}" ] || [ "${container_owner}" != "${task_owner}" ]; then
	echo "created container ownership mismatch" >&2
	exit 1
fi

docker exec \
  --env CDNCA_CACHE_TASK_SMOKE=1 \
  --env CDNCA_OPENRESTY_BIN=/usr/local/openresty/bin/openresty \
  --env CDNCA_CACHE_TASK_TEMPLATE=/fixtures/cache-task-smoke.conf.tmpl \
  "${container_id}" \
  /usr/local/bin/cachetask-smoke.test -test.run "${test_run}" -test.v

printf 'runtime_image=%s\nopenresty_version=%s\n' "${OPENRESTY_IMAGE}" "${OPENRESTY_VERSION}"

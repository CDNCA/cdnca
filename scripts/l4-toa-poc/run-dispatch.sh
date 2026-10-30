#!/bin/sh
# TOA on a port shared by two streams (TLS passthrough by SNI + plain), i.e.
# the dispatcher -> PROXY unix socket -> per-stream server path, in a real
# OpenResty running the runtime l4runtime.CompileV2 renders (mounted at
# /work/render: nginx.conf + config.json from TestRenderTOADispatchRuntime).
# Mounts: this directory at /work/poc, internal/toa/bpf at /bpf,
# edge/openresty/l4geo at /opt/cdnca/l4geo; /work/alirx/toa-kern.o is the
# origin-side receiver (built separately, not part of the repository).
set -u
P=/work/poc
OR=/usr/local/openresty/bin/openresty
PREFIX=/var/lib/cdnca-edge/l4-toa-dispatch/
CG=/sys/fs/cgroup/cdnca-toa-dispatch
OCG=/sys/fs/cgroup/origin-toa-dispatch
PIN=/sys/fs/bpf/cdnca-toa-dispatch
log() { printf '\n=== %s\n' "$*"; }
killmatch() {
	for p in /proc/[0-9]*; do
		case "$( (tr '\0' ' ' < "$p/cmdline") 2>/dev/null)" in *"$1"*) kill "${p#/proc/}" 2>/dev/null;; esac
	done
}
cleanup() {
	[ -f ${PREFIX}nginx.pid ] && kill "$(cat ${PREFIX}nginx.pid)" 2>/dev/null
	killmatch peer_origin; sleep 1
	for c in $CG $OCG; do
		for t in sock_ops setsockopt getpeername4 getpeername6; do
			for id in $(bpftool cgroup show $c 2>/dev/null | awk -v t=$t '$2==t{print $1}'); do bpftool cgroup detach $c $t id $id; done
		done
	done
	rm -rf $PIN /sys/fs/bpf/alitoa-dispatch
	ip netns del cli 2>/dev/null; ip netns del org 2>/dev/null
	ip link del vc-e 2>/dev/null; ip link del vo-e 2>/dev/null
	rmdir $CG $OCG 2>/dev/null
}
cleanup
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

log "topology"
ip netns add cli; ip netns add org
ip link add vc type veth peer name vc-e; ip link set vc netns cli
ip link add vo type veth peer name vo-e; ip link set vo netns org
ip addr add 10.10.1.1/24 dev vc-e; ip link set vc-e up
ip addr add 10.10.2.1/24 dev vo-e; ip link set vo-e up
ip -n cli addr add 10.10.1.2/24 dev vc; ip -n cli link set vc up; ip -n cli link set lo up
ip -n cli route add default via 10.10.1.1
ip -n org addr add 10.10.2.2/24 dev vo; ip -n org link set vo up; ip -n org link set lo up

log "origin with the TOA receiver (getpeername returns the TOA address)"
mkdir -p $OCG
bpftool prog loadall /work/alirx/toa-kern.o /sys/fs/bpf/alitoa-dispatch || exit 1
bpftool cgroup attach $OCG sock_ops pinned /sys/fs/bpf/alitoa-dispatch/toa_parse multi
bpftool cgroup attach $OCG getpeername4 pinned /sys/fs/bpf/alitoa-dispatch/toa_peername4 multi
cat > /tmp/peer_origin.py <<'EOF'
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        peer = self.request.getpeername()
        self.request.sendall(f"{peer[0]}:{peer[1]}\n".encode())
        while self.request.recv(4096):
            pass
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
S(("0.0.0.0", 8000), H).serve_forever()
EOF
sh -c "echo \$\$ > $OCG/cgroup.procs; exec ip netns exec org python3 /tmp/peer_origin.py" &
sleep 1

log "edge: TOA programs on the OpenResty cgroup, then the rendered runtime"
mkdir -p $CG $PIN
bpftool prog loadall /bpf/toa.bpf.o $PIN pinmaps $PIN/maps || exit 1
bpftool cgroup attach $CG setsockopt pinned $PIN/cdnca_toa_setsockopt multi
bpftool cgroup attach $CG sock_ops pinned $PIN/cdnca_toa_sockops multi
rm -rf $PREFIX; mkdir -p ${PREFIX}logs /var/lib/cdnca-edge/shared/l4mux
chmod 0711 /var/lib/cdnca-edge/shared/l4mux
grep -o 'access_log "[^"]*"' /work/render/nginx.conf | cut -d'"' -f2 | while read -r f; do mkdir -p "$(dirname "$f")"; done
cp /work/render/nginx.conf /work/render/config.json $PREFIX
$OR -e stderr -t -q -p $PREFIX -c nginx.conf -g "pid ${PREFIX}nginx.pid;" || exit 1
sh -c "echo \$\$ > $CG/cgroup.procs; exec $OR -e ${PREFIX}logs/error.log -p $PREFIX -c nginx.conf -g 'pid ${PREFIX}nginx.pid;'"
sleep 2
ls -l /var/lib/cdnca-edge/shared/l4mux

cat > /tmp/dispatch_client.py <<'EOF'
import socket, ssl, sys
mode = sys.argv[1]
s = socket.create_connection(("10.10.1.1", 9443), timeout=5)
if mode == "tls":
    # Send only a real ClientHello carrying SNI toa.example: enough for the
    # dispatcher's ssl_preread; the origin is plain TCP and answers first.
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname="toa.example")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    s.sendall(outgoing.read())
else:
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
local = s.getsockname()
reply = s.makefile("rb").readline().decode().strip()
print(f"{mode}: client={local[0]}:{local[1]} origin_saw={reply}")
EOF
log "1. TLS (SNI toa.example) through the dispatcher"
ip netns exec cli python3 /tmp/dispatch_client.py tls
log "2. plain TCP through the dispatcher"
ip netns exec cli python3 /tmp/dispatch_client.py plain
log "stats (stored, skip_v6_client, skip_v6_upstream, bad_optlen, written, no_space, done)"
bpftool map dump pinned $PIN/maps/cdnca_toa_stats | grep -o '"value": [0-9]*' | tr '\n' ' '; echo
grep -E "CDNCA_TOA|emerg|alert|crit" ${PREFIX}logs/error.log | head -5
cleanup

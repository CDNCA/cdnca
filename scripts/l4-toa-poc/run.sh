#!/bin/sh
# TOA PoC: client ns -> edge (patched nginx in a BPF cgroup) -> origin ns.
# See docs/architecture/l4-toa-poc.md. Mounts: this directory at /work/poc,
# agents/edge-agent/internal/toa/bpf at /bpf; ORIGIN_TOA=1 additionally needs
# a separately downloaded and built origin receiver at /work/alirx/toa-kern.o.
set -u
P=/work/poc
O=/build/out
CG=/sys/fs/cgroup/cdnca-toa-poc
PIN=/sys/fs/bpf/cdnca-toa-poc
OCG=/sys/fs/cgroup/origin-toa-poc
log() { printf '\n=== %s\n' "$*"; }

killmatch() {
	for p in /proc/[0-9]*; do
		case "$( (tr '\0' ' ' < "$p/cmdline") 2>/dev/null)" in *"$1"*) kill "${p#/proc/}" 2>/dev/null;; esac
	done
}
cleanup() {
	[ -f $O/logs/nginx.pid ] && kill "$(cat $O/logs/nginx.pid)" 2>/dev/null
	killmatch origin.py; killmatch tcpdump; killmatch client.py
	sleep 1
	bpftool cgroup detach $CG sock_ops pinned $PIN/sockops 2>/dev/null
	bpftool cgroup detach $CG setsockopt pinned $PIN/setsockopt 2>/dev/null
	rm -rf $PIN
	for t in sock_ops getpeername4 getpeername6; do
		for id in $(bpftool cgroup show $OCG 2>/dev/null | awk -v t=$t '$2==t{print $1}'); do bpftool cgroup detach $OCG $t id $id; done
	done
	rm -rf /sys/fs/bpf/alitoa; rmdir $OCG 2>/dev/null
	ip netns del cli 2>/dev/null; ip netns del org 2>/dev/null
	ip link del vc-e 2>/dev/null; ip link del vo-e 2>/dev/null
	rmdir $CG 2>/dev/null
}
cleanup
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

log "topology"
ip netns add cli; ip netns add org
ip link add vc type veth peer name vc-e; ip link set vc netns cli
ip link add vo type veth peer name vo-e; ip link set vo netns org
ip addr add 10.10.1.1/24 dev vc-e; ip -6 addr add fd00:1::1/64 dev vc-e nodad; ip link set vc-e up
ip addr add 10.10.2.1/24 dev vo-e; ip link set vo-e up
ip -n cli addr add 10.10.1.2/24 dev vc; ip -n cli -6 addr add fd00:1::2/64 dev vc nodad
ip -n cli link set vc up; ip -n cli link set lo up
ip -n cli route add default via 10.10.1.1; ip -n cli -6 route add default via fd00:1::1
ip -n org addr add 10.10.2.2/24 dev vo; ip -n org link set vo up; ip -n org link set lo up

mkdir -p $OCG
if [ "${ORIGIN_TOA:-}" = 1 ]; then
	log "origin: Alibaba eBPF TOA receiver (BSD-2, built in /tmp only) on $OCG"
	bpftool prog loadall /work/alirx/toa-kern.o /sys/fs/bpf/alitoa || exit 1
	bpftool cgroup attach $OCG sock_ops pinned /sys/fs/bpf/alitoa/toa_parse multi
	bpftool cgroup attach $OCG getpeername4 pinned /sys/fs/bpf/alitoa/toa_peername4 multi
	bpftool cgroup attach $OCG getpeername6 pinned /sys/fs/bpf/alitoa/toa_peername6 multi
fi
sh -c "echo \$\$ > $OCG/cgroup.procs; exec ip netns exec org python3 $P/origin.py 8000" &
sleep 1

log "nginx (patched) in cgroup $CG"
mkdir -p $CG
cat > $O/conf/nginx.conf <<'EOF'
user root;
worker_processes 2;
error_log /build/out/logs/error.log notice;
events { worker_connections 1024; }
stream {
    server { listen 9000; listen [::]:9000 ipv6only=on; proxy_pass 10.10.2.2:8000; proxy_toa on; }
    server { listen 9001; proxy_pass 10.10.2.2:8000; }
    server { listen 9002; proxy_pass 10.10.2.2:8000; proxy_toa on; proxy_protocol on; }
}
EOF
: > $O/logs/error.log
sh -c "echo \$\$ > $CG/cgroup.procs; exec $O/sbin/nginx"
sleep 1
echo "nginx pids in cgroup: $(cat $CG/cgroup.procs | tr '\n' ' ')"

log "1. hold a connection open BEFORE the BPF programs are attached"
rm -f /tmp/hold.fifo; mkfifo /tmp/hold.fifo
ip netns exec cli python3 $P/client.py 10.10.1.1 9000 hold /tmp/hold.fifo > /tmp/hold.out &
sleep 1; cat /tmp/hold.out

log "2. no BPF attached: proxy_toa must not break forwarding"
ip netns exec cli python3 $P/client.py 10.10.1.1 9000 peer
grep CDNCA_TOA $O/logs/error.log | sed 's/^.*\[warn\]/[warn]/'

log "attach BPF (cgroup/setsockopt + sockops, multi)"
mkdir -p $PIN
bpftool prog loadall /bpf/toa.bpf.o $PIN pinmaps $PIN/maps || exit 1
bpftool cgroup attach $CG setsockopt pinned $PIN/cdnca_toa_setsockopt multi
bpftool cgroup attach $CG sock_ops pinned $PIN/cdnca_toa_sockops multi
mv $PIN/cdnca_toa_setsockopt $PIN/setsockopt; mv $PIN/cdnca_toa_sockops $PIN/sockops
bpftool cgroup show $CG

rm -f /tmp/toa.pcap
ip netns exec org tcpdump -Z root -U -i vo -s 160 -w /tmp/toa.pcap tcp port 8000 2>/tmp/tcpdump.err &
for i in 1 2 3 4 5 6 7 8 9 10; do grep -q listening /tmp/tcpdump.err 2>/dev/null && break; sleep 1; done
sleep 1

log "3. IPv4 client via TOA listener"
ip netns exec cli python3 $P/client.py 10.10.1.1 9000 peer
log "4. IPv4 client via control listener (no proxy_toa)"
ip netns exec cli python3 $P/client.py 10.10.1.1 9001 peer
log "5. IPv6 client via TOA listener (IPv4 upstream)"
ip netns exec cli python3 $P/client.py fd00:1::1 9000 peer
log "6. bulk 4 MiB through TOA listener (MSS/segmentation)"
ip netns exec cli python3 $P/client.py 10.10.1.1 9000 bulk 4194304
log "7. pre-existing connection after attach"
echo go > /tmp/hold.fifo; sleep 1; cat /tmp/hold.out
log "8. TOA + PROXY protocol together (kernel level only)"
ip netns exec cli python3 -c "import socket;s=socket.create_connection(('10.10.1.1',9002));s.sendall(b'PEER\n');print('origin reply:',s.recv(200))"

sleep 1; killmatch tcpdump; sleep 1
log "upstream packets (edge -> origin) with TCP options"
python3 $P/pcap_toa.py /tmp/toa.pcap | grep '^10.10.2.1:'
log "stats (stored, skip_v6_client, skip_v6_upstream, bad_optlen, written, no_space, done)"
bpftool map dump pinned $PIN/maps/cdnca_toa_stats | grep -o '"value": [0-9]*' | tr '\n' ' '; echo
cleanup

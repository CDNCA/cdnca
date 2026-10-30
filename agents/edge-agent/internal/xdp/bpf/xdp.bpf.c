// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * cdnca node XDP filter (r136 xdp): the NIC-side front of the node DDoS
 * table inet cdnca_ddos (agents/edge-agent/internal/ddos). It drops, before
 * the stack allocates anything:
 *   - blocked clients (cdnca_xdp_block, LPM over IPv4-mapped/IPv6
 *     addresses): every packet, the auto defense L5;
 *   - banned clients (cdnca_xdp_ban, LPM): the protected TCP ports, like
 *     the nft ban sets (empty connection and rate bans);
 *   - port bans (cdnca_xdp_portban: one client on one port, the CC kernel
 *     bans);
 *   - malformed TCP flag combinations on the protected ports, the same
 *     classes as the nft packet filters (null, xmas, syn_fin, syn_rst, all;
 *     fin and conntrack INVALID need connection state and stay in nft);
 *   - level D sites (攻击自动升级 D 级): every TCP packet to a port only
 *     such sites use, and TLS ClientHellos naming such a site on a shared
 *     port (cdnca_xdp_site_ports / cdnca_xdp_sni_ports / cdnca_xdp_sni),
 *     before the exempt networks;
 *   - new connections (SYN) over the per client rate (a fixed one second
 *     window; IPv6 clients by /64), banning the client for a while when set.
 * Exempt networks (node networks, allow list) always pass. Without a DDoS
 * spec (no protected port) the program still enforces blocks and port bans. Everything else
 * passes on to nftables, which keeps enforcing the same rules: XDP only
 * moves the drops earlier. Original cdnca code.
 */
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* struct cdnca_xdp_config.tcp_flags bits (xdp.go FlagNull...). */
#define FLAG_NULL (1u << 0)
#define FLAG_XMAS (1u << 1)
#define FLAG_SYN_FIN (1u << 2)
#define FLAG_SYN_RST (1u << 3)
#define FLAG_ALL (1u << 4)

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#define NS_PER_SECOND 1000000000ULL

/* Stat indexes mirror xdp.go stat*. */
enum cdnca_xdp_stat {
	STAT_BLOCK = 0,
	STAT_BAN,
	STAT_PORT_BAN,
	STAT_RATE,
	STAT_TCP_NULL,
	STAT_TCP_XMAS,
	STAT_TCP_SYN_FIN,
	STAT_TCP_SYN_RST,
	STAT_TCP_ALL,
	STAT_COUNT,
};

struct cdnca_xdp_config {
	__u32 enabled;
	__u32 tcp_flags;
	__u32 syn_rate;        /* new connections a second per client, 0 off */
	__u32 syn_ban_seconds; /* ban over the rate, 0: only drop the excess */
	__u64 generation;      /* the agent reads it back to verify the map */
};

struct cdnca_xdp_lpm_key {
	__u32 prefixlen; /* IPv4 is mapped: ::ffff:a.b.c.d, prefixlen + 96 */
	__u8 addr[16];
};

struct cdnca_xdp_port_key {
	__u8 addr[16];
	__u16 port; /* host order */
	__u16 pad;
};

struct cdnca_xdp_rate {
	__u64 window;
	__u64 banned_until;
	__u32 count;
	__u32 pad;
};

struct cdnca_xdp_counter {
	__u64 packets;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cdnca_xdp_config);
} cdnca_xdp_cfg SEC(".maps");

/* Protected TCP destination ports: bit (port & 31) of word port >> 5. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2048);
	__type(key, __u32);
	__type(value, __u32);
} cdnca_xdp_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cdnca_xdp_lpm_key);
	__type(value, __u8);
} cdnca_xdp_exempt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 262144);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cdnca_xdp_lpm_key);
	__type(value, __u64); /* until, CLOCK_MONOTONIC ns (bpf_ktime_get_ns) */
} cdnca_xdp_ban SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cdnca_xdp_lpm_key);
	__type(value, __u64);
} cdnca_xdp_block SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cdnca_xdp_port_key);
	__type(value, __u64);
} cdnca_xdp_portban SEC(".maps");

/* Per client (IPv4 address, IPv6 /64) new connection window. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__type(key, struct cdnca_xdp_port_key);
	__type(value, struct cdnca_xdp_rate);
} cdnca_xdp_rate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_COUNT);
	__type(key, __u32);
	__type(value, struct cdnca_xdp_counter);
} cdnca_xdp_stats SEC(".maps");

/* Site drop (攻击自动升级 D 级, esc-node §3): TCP destination ports every
 * packet of which is dropped (ports only level D sites use), same bitmap
 * layout as cdnca_xdp_ports. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2048);
	__type(key, __u32);
	__type(value, __u32);
} cdnca_xdp_site_ports SEC(".maps");

/* Shared TLS ports whose ClientHello SNI is looked up in cdnca_xdp_sni. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2048);
	__type(key, __u32);
	__type(value, __u32);
} cdnca_xdp_sni_ports SEC(".maps");

/* Server names by sni_hash (FNV-1a 64 over the lower case name read from
 * its last byte to its first): SNI_* bits. A leading wildcard *.example.com
 * is stored under the hash of example.com with a *_WILDCARD bit. KEEP bits
 * are the names of the other sites on the shared ports: nginx prefers an
 * exact name to a wildcard and a longer wildcard to a shorter one, so does
 * the program. */
#define SNI_DROP_EXACT 1
#define SNI_DROP_WILDCARD 2
#define SNI_KEEP_EXACT 4
#define SNI_KEEP_WILDCARD 8
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, __u8);
} cdnca_xdp_sni SEC(".maps");

#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME 0x100000001b3ULL
/* Offsets past this (from the frame start) are not parsed: pass. */
#define SNI_MAX_OFFSET 2048
#define SNI_MAX_NAME 253
#define SNI_MAX_EXTENSIONS 64

struct vlan_hdr {
	__be16 tci;
	__be16 proto;
};

/* Site drop counters (xdp.go SiteDropCounters), apart from cdnca_xdp_stats:
 * the node telemetry drop kinds stay as they are. */
enum cdnca_xdp_site_stat {
	SITE_STAT_PORT = 0,
	SITE_STAT_SNI,
	SITE_STAT_COUNT,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SITE_STAT_COUNT);
	__type(key, __u32);
	__type(value, struct cdnca_xdp_counter);
} cdnca_xdp_site_stats SEC(".maps");

static __always_inline int site_drop(__u32 stat, __u64 bytes)
{
	struct cdnca_xdp_counter *counter = bpf_map_lookup_elem(&cdnca_xdp_site_stats, &stat);
	if (counter) {
		counter->packets++;
		counter->bytes += bytes;
	}
	return XDP_DROP;
}

static __always_inline int port_listed(void *map, __u16 port)
{
	__u32 word = port >> 5;
	__u32 *bits = bpf_map_lookup_elem(map, &word);
	return bits && (*bits & (1u << (port & 31)));
}

/* byte_at reads the frame byte at off (-1 past the end). The mask, behind
 * a compiler barrier, gives the verifier a bounded offset whatever clang
 * proved about off. */
static __always_inline int byte_at(void *data, void *end, __u32 off)
{
	asm volatile("%0 &= 0xfff" : "+r"(off));
	__u8 *c = data + off;
	if ((void *)(c + 1) > end)
		return -1;
	return *c;
}

static __always_inline int u16_at(void *data, void *end, __u32 off)
{
	int high = byte_at(data, end, off);
	int low = byte_at(data, end, off + 1);
	if (high < 0 || low < 0)
		return -1;
	return (high << 8) | low;
}

/* The ClientHello is parsed by two global functions: the verifier checks
 * each once on its own (scalar arguments), instead of every path of the
 * extension walk times the name walk. */

/* cdnca_sni_locate returns (name offset << 8) | name length of the
 * server_name of the TLS ClientHello at frame offset off, 0 when there is
 * none in this segment. */
__attribute__((noinline)) int cdnca_sni_locate(struct xdp_md *ctx, __u32 off)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	if (off > 256)
		return 0;
	/* record header 5, handshake header 4, version 2, random 32, session id length 1 */
	if (byte_at(data, end, off) != 0x16 || byte_at(data, end, off + 5) != 0x01)
		return 0;
	int sid = byte_at(data, end, off + 43);
	if (sid < 0 || sid > 32)
		return 0;
	off += 44 + sid;
	int length = u16_at(data, end, off); /* cipher suites */
	if (length < 0)
		return 0;
	off += 2 + length;
	if (off > SNI_MAX_OFFSET)
		return 0;
	length = byte_at(data, end, off); /* compression methods */
	if (length < 0)
		return 0;
	off += 1 + length + 2; /* and the extensions length */
	for (int i = 0; i < SNI_MAX_EXTENSIONS; i++) {
		if (off > SNI_MAX_OFFSET)
			return 0;
		int type = u16_at(data, end, off);
		length = u16_at(data, end, off + 2);
		if (type < 0 || length < 0)
			return 0;
		off += 4;
		if (type != 0) {
			off += length;
			continue;
		}
		/* server_name_list length 2, name type 1 (host_name 0), name length 2 */
		if (off > SNI_MAX_OFFSET || byte_at(data, end, off + 2) != 0)
			return 0;
		length = u16_at(data, end, off + 3);
		if (length <= 0 || length > SNI_MAX_NAME)
			return 0;
		return (int)((off + 5) << 8) | length;
	}
	return 0;
}

/* cdnca_sni_verdict is 1 when the name at frame offset start (length
 * bytes) is dropped. Walking from the last byte, every dot looks the labels
 * after it up: the last wildcard found (the longest) decides, an exact
 * entry overrides it. */
__attribute__((noinline)) int cdnca_sni_verdict(struct xdp_md *ctx, __u32 start, __u32 length)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	if (length == 0 || length > SNI_MAX_NAME || start > SNI_MAX_OFFSET + 5)
		return 0;
	__u32 last = start + length - 1;
	__u64 hash = FNV_OFFSET;
	__u32 wildcard = 0;
	for (__u32 i = 0; i < SNI_MAX_NAME; i++) {
		if (i >= length)
			break;
		int ch = byte_at(data, end, last - i);
		if (ch < 0)
			return 0;
		if (ch == '.' && i > 0 && i + 1 < length) {
			__u8 *flags = bpf_map_lookup_elem(&cdnca_xdp_sni, &hash);
			if (flags && (*flags & (SNI_DROP_WILDCARD | SNI_KEEP_WILDCARD)))
				wildcard = *flags & (SNI_DROP_WILDCARD | SNI_KEEP_WILDCARD);
		}
		if (ch >= 'A' && ch <= 'Z')
			ch |= 0x20;
		hash ^= (__u8)ch;
		hash *= FNV_PRIME;
	}
	__u8 *flags = bpf_map_lookup_elem(&cdnca_xdp_sni, &hash);
	if (flags && (*flags & SNI_KEEP_EXACT))
		return 0;
	if (flags && (*flags & SNI_DROP_EXACT))
		return 1;
	return (wildcard & SNI_DROP_WILDCARD) && !(wildcard & SNI_KEEP_WILDCARD);
}

/* sni_dropped: the ClientHello at off names a dropped server. Anything else
 * (no handshake, a hello split before its server_name, no SNI) passes:
 * OpenResty still closes such handshakes (esc-node §4). */
static __always_inline int sni_dropped(struct xdp_md *ctx, __u32 off)
{
	int located = cdnca_sni_locate(ctx, off);
	if (located <= 0)
		return 0;
	return cdnca_sni_verdict(ctx, (__u32)located >> 8, (__u32)located & 0xff);
}

static __always_inline int drop(__u32 stat, __u64 bytes)
{
	struct cdnca_xdp_counter *counter = bpf_map_lookup_elem(&cdnca_xdp_stats, &stat);
	if (counter) {
		counter->packets++;
		counter->bytes += bytes;
	}
	return XDP_DROP;
}

SEC("xdp")
int cdnca_xdp_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	__u64 bytes = end - data;
	__u32 zero = 0;
	struct cdnca_xdp_config *cfg = bpf_map_lookup_elem(&cdnca_xdp_cfg, &zero);
	if (!cfg || !cfg->enabled)
		return XDP_PASS;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return XDP_PASS;
	__u16 proto = eth->h_proto;
	void *l3 = eth + 1;
	__u32 l4off = sizeof(*eth); /* frame offset of the L4 header */
	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan = l3;
		if ((void *)(vlan + 1) > end)
			return XDP_PASS;
		proto = vlan->proto;
		l3 = vlan + 1;
		l4off += sizeof(*vlan);
	}

	struct cdnca_xdp_lpm_key key = {.prefixlen = 128};
	__u8 l4proto;
	void *l4;
	int first_fragment = 1;
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = l3;
		if ((void *)(ip + 1) > end || ip->ihl < 5)
			return XDP_PASS;
		key.addr[10] = 0xff;
		key.addr[11] = 0xff;
		__builtin_memcpy(&key.addr[12], &ip->saddr, 4);
		l4proto = ip->protocol;
		l4 = (void *)ip + ip->ihl * 4;
		l4off += ip->ihl * 4;
		if (ip->frag_off & bpf_htons(0x1fff))
			first_fragment = 0;
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = l3;
		if ((void *)(ip6 + 1) > end)
			return XDP_PASS;
		__builtin_memcpy(key.addr, &ip6->saddr, 16);
		/* Extension headers are not walked: such packets get only the
		 * address checks here, nftables still applies the rest. */
		l4proto = ip6->nexthdr;
		l4 = ip6 + 1;
		l4off += sizeof(*ip6);
	} else {
		return XDP_PASS;
	}

	/* Site drop first: a level D site is a black hole for every client
	 * (exempt networks too; the node's own probes run on lo). */
	if (l4proto == IPPROTO_TCP && first_fragment) {
		struct tcphdr *seg = l4;
		if ((void *)(seg + 1) > end)
			return XDP_PASS;
		__u16 dport = bpf_ntohs(seg->dest);
		if (port_listed(&cdnca_xdp_site_ports, dport))
			return site_drop(SITE_STAT_PORT, bytes);
		if (port_listed(&cdnca_xdp_sni_ports, dport)) {
			__u32 payload = l4off + seg->doff * 4;
			if (sni_dropped(ctx, payload))
				return site_drop(SITE_STAT_SNI, bytes);
		}
	}

	if (bpf_map_lookup_elem(&cdnca_xdp_exempt, &key))
		return XDP_PASS;
	__u64 now = bpf_ktime_get_ns();
	__u64 *until = bpf_map_lookup_elem(&cdnca_xdp_block, &key);
	if (until && *until > now)
		return drop(STAT_BLOCK, bytes);

	if (l4proto != IPPROTO_TCP || !first_fragment)
		return XDP_PASS;
	struct tcphdr *tcp = l4;
	if ((void *)(tcp + 1) > end)
		return XDP_PASS;
	__u16 port = bpf_ntohs(tcp->dest);
	/* Port bans name their port: no protected port set needed. */
	struct cdnca_xdp_port_key client = {.port = port};
	__builtin_memcpy(client.addr, key.addr, 16);
	until = bpf_map_lookup_elem(&cdnca_xdp_portban, &client);
	if (until && *until > now)
		return drop(STAT_PORT_BAN, bytes);
	__u32 word = port >> 5;
	__u32 *bits = bpf_map_lookup_elem(&cdnca_xdp_ports, &word);
	if (!bits || !(*bits & (1u << (port & 31))))
		return XDP_PASS;

	/* Then the nft guard chain's order: flag classes, bans, rates. */
	__u8 flags = ((__u8 *)tcp)[13] & 0x3f;
	__u32 filters = cfg->tcp_flags;
	if ((filters & FLAG_NULL) && flags == 0)
		return drop(STAT_TCP_NULL, bytes);
	if ((filters & FLAG_XMAS) && flags == (TCP_FIN | TCP_PSH | TCP_URG))
		return drop(STAT_TCP_XMAS, bytes);
	if ((filters & FLAG_ALL) && flags == 0x3f)
		return drop(STAT_TCP_ALL, bytes);
	if ((filters & FLAG_SYN_FIN) && (flags & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN))
		return drop(STAT_TCP_SYN_FIN, bytes);
	if ((filters & FLAG_SYN_RST) && (flags & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST))
		return drop(STAT_TCP_SYN_RST, bytes);
	until = bpf_map_lookup_elem(&cdnca_xdp_ban, &key);
	if (until && *until > now)
		return drop(STAT_BAN, bytes);

	__u32 rate = cfg->syn_rate;
	if (!rate)
		return XDP_PASS;
	client.port = 0;
	if (proto == bpf_htons(ETH_P_IPV6))
		__builtin_memset(&client.addr[8], 0, 8);
	struct cdnca_xdp_rate *window = bpf_map_lookup_elem(&cdnca_xdp_rate, &client);
	if (window && window->banned_until > now)
		return drop(STAT_RATE, bytes);
	if ((flags & (TCP_SYN | TCP_ACK | TCP_RST | TCP_FIN)) != TCP_SYN)
		return XDP_PASS;
	if (!window) {
		struct cdnca_xdp_rate first = {.window = now, .count = 1};
		bpf_map_update_elem(&cdnca_xdp_rate, &client, &first, BPF_ANY);
		return XDP_PASS;
	}
	if (now - window->window >= NS_PER_SECOND) {
		window->window = now;
		window->count = 0;
	}
	/* Plain read-modify-write: fetching atomics need BPF v3 (5.12); a
	 * lost increment under a race across CPUs only lets a SYN through,
	 * nftables still counts it. */
	if (window->count >= rate) {
		if (cfg->syn_ban_seconds)
			window->banned_until = now + (__u64)cfg->syn_ban_seconds * NS_PER_SECOND;
		return drop(STAT_RATE, bytes);
	}
	window->count++;
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

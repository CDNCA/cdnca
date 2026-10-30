// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * CDNCA L4 TOA sender (node side).
 *
 * Original CDNCA code; no third-party source is copied here.  The option
 * format (kind 254, length 8: 2-byte port + 4-byte IPv4, network order)
 * matches the de-facto TOA wire format read by the origin-side modules
 * documented in docs/user/l4-toa.md.  The dual license keeps the program
 * loadable by the kernel (GPL-compatible) without imposing GPL on the agent.
 *
 * Flow:
 *   1. The patched OpenResty stream proxy (proxy_toa on) calls
 *      setsockopt(fd, IPPROTO_TCP, CDNCA_TOA_SOCKOPT, &client, 20) on the
 *      upstream socket before connect().
 *   2. cdnca_toa_setsockopt (cgroup/setsockopt) consumes the call, keeps the
 *      client address in socket-local storage and bypasses the kernel.
 *   3. cdnca_toa_sockops (sockops) arms the header-option callbacks once the
 *      handshake completes (never on the SYN), writes the option on the
 *      handshake ACK and following segments, and disarms as soon as the
 *      origin has evidently created its socket (data acked or received).
 *
 * Sockets that never made the private setsockopt call are untouched, so
 * attaching to a cgroup does not affect existing or unrelated connections.
 */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define CDNCA_TOA_SOCKOPT 0x43464c54 /* "CFLT"; see the cdnca-stream-toa native patch */
#define CDNCA_SOL_TCP 6
#define CDNCA_AF_INET 2
#define CDNCA_AF_INET6 10
#define TOA_KIND 254
#define TOA_LEN 8

/* Layout shared with the nginx patch (ngx_cdnca_toa_sockopt_t). */
struct cdnca_toa_sockopt {
	__u16 family; /* host order */
	__u16 port;   /* network order */
	__u8 addr[16];
};

struct toa_state {
	__u32 addr; /* network order */
	__u16 port; /* network order */
	__u16 armed;
};

struct toa_option {
	__u8 kind;
	__u8 len;
	__u16 port;
	__u32 addr;
} __attribute__((packed));

enum toa_stat {
	STAT_STORED = 0,       /* setsockopt accepted an IPv4 client */
	STAT_SKIP_V6_CLIENT,   /* IPv6 client: TOA carries IPv4 only */
	STAT_SKIP_V6_UPSTREAM, /* upstream socket is not AF_INET */
	STAT_BAD_OPTLEN,       /* malformed private setsockopt */
	STAT_WRITTEN,          /* segments carrying the option */
	STAT_NO_SPACE,         /* TCP option space exhausted */
	STAT_DONE,             /* connections disarmed after handshake */
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct toa_state);
} cdnca_toa_sk SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} cdnca_toa_stats SEC(".maps");

static __always_inline void stat_inc(__u32 index)
{
	__u64 *value = bpf_map_lookup_elem(&cdnca_toa_stats, &index);

	if (value)
		__sync_fetch_and_add(value, 1);
}

SEC("cgroup/setsockopt")
int cdnca_toa_setsockopt(struct bpf_sockopt *ctx)
{
	struct cdnca_toa_sockopt *in = ctx->optval;
	struct bpf_sock *sk = ctx->sk;
	struct toa_state *state;

	if (ctx->level != CDNCA_SOL_TCP || ctx->optname != CDNCA_TOA_SOCKOPT)
		return 1; /* not ours: let the kernel handle it */

	if (ctx->optlen != sizeof(*in) || (void *)(in + 1) > ctx->optval_end) {
		stat_inc(STAT_BAD_OPTLEN);
		return 0; /* EPERM; nginx logs once and connects without TOA */
	}

	/* Consume the private option in every remaining case. */
	ctx->optlen = -1;

	if (!sk || sk->family != CDNCA_AF_INET) {
		stat_inc(STAT_SKIP_V6_UPSTREAM);
		return 1;
	}
	if (in->family != CDNCA_AF_INET) {
		stat_inc(STAT_SKIP_V6_CLIENT);
		return 1;
	}

	state = bpf_sk_storage_get(&cdnca_toa_sk, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (!state)
		return 1;
	__builtin_memcpy(&state->addr, in->addr, 4);
	state->port = in->port;
	state->armed = 0;
	stat_inc(STAT_STORED);
	return 1;
}

SEC("sockops")
int cdnca_toa_sockops(struct bpf_sock_ops *skops)
{
	struct bpf_sock *sk = skops->sk;
	struct toa_state *state;
	struct toa_option opt;

	if (!sk)
		return 1;
	state = bpf_sk_storage_get(&cdnca_toa_sk, sk, 0, 0);
	if (!state)
		return 1;

	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		/* After the SYN-ACK, before the handshake ACK is sent. */
		state->armed = 1;
		bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags |
						 BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
		break;
	case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
		if (!state->armed)
			break;
		/* bytes_acked counts the SYN as 1; >1 means our data was acked. */
		if (skops->bytes_acked > 1 || skops->bytes_received > 0) {
			state->armed = 0;
			bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags &
							 ~BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
			stat_inc(STAT_DONE);
			break;
		}
		if (bpf_reserve_hdr_opt(skops, TOA_LEN, 0))
			stat_inc(STAT_NO_SPACE);
		break;
	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
		if (!state->armed)
			break;
		opt.kind = TOA_KIND;
		opt.len = TOA_LEN;
		opt.port = state->port;
		opt.addr = state->addr;
		if (bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0) == 0)
			stat_inc(STAT_WRITTEN);
		break;
	}
	return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

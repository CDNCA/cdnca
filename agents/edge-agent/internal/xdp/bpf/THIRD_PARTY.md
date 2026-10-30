# XDP filter eBPF program: licensing

| File | Origin | License |
| --- | --- | --- |
| `xdp.bpf.c` | Original cdnca code | `GPL-2.0-only OR BSD-2-Clause` (SPDX header) |
| `xdp.bpf.o` | Built from `xdp.bpf.c` by `build.sh` (pinned in `SHA256SUMS`) | Same as source |
| `<bpf/bpf_helpers.h>`, `<bpf/bpf_endian.h>` (build-time headers, not vendored) | libbpf | `LGPL-2.1 OR BSD-2-Clause` |
| `<linux/*.h>` (build-time UAPI headers, not vendored) | Linux kernel UAPI | `GPL-2.0 WITH Linux-syscall-note` |

The object declares `Dual BSD/GPL`; the Go agent loads it through
`github.com/cilium/ebpf` (MIT, v0.19.0, already pinned in go.mod for TOA), so
no new dependency is added.

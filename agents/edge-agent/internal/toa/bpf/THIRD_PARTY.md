# TOA eBPF program: licensing

| File | Origin | License |
| --- | --- | --- |
| `toa.bpf.c` | Original CDNCA code | `GPL-2.0-only OR BSD-2-Clause` (SPDX header) |
| `toa.bpf.o` | Built from `toa.bpf.c` by `build.sh` (pinned in `SHA256SUMS`) | Same as source |
| `<bpf/bpf_helpers.h>` (build-time header, not vendored) | libbpf | `LGPL-2.1 OR BSD-2-Clause` |
| `<linux/bpf.h>` (build-time UAPI header, not vendored) | Linux kernel UAPI | `GPL-2.0 WITH Linux-syscall-note` |

The kernel only loads programs whose `license` section is GPL-compatible
when they call GPL-only helpers; the object declares `Dual BSD/GPL`. The dual
license keeps the program loadable without placing the Go agent, which loads
it through `github.com/cilium/ebpf` (MIT), under the GPL.

No third-party TOA source is copied into this repository. The wire format
(TCP option kind 254, length 8: 2-byte port + 4-byte IPv4, network order) is
the interoperable format read by the origin-side receivers listed in
`docs/user/l4-toa.md`; those are GPL-2.0 projects (Alibaba Cloud's `toa-ebpf`
source files carry a BSD-2-Clause header) that customers build and load on
their own origin servers. CDNCA does not redistribute them.

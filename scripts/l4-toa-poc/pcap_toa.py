#!/usr/bin/env python3
# Parse a classic pcap (Ethernet / Linux cooked) and report TCP option 254.
import socket, struct, sys

data = open(sys.argv[1], "rb").read()
magic = struct.unpack("<I", data[:4])[0]
endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
linktype = struct.unpack(endian + "I", data[20:24])[0]
off = 24
rows = []
while off + 16 <= len(data):
    _, _, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
    pkt = data[off + 16:off + 16 + incl]
    off += 16 + incl
    if linktype == 1:
        if struct.unpack("!H", pkt[12:14])[0] != 0x0800:
            continue
        ip = pkt[14:]
    elif linktype == 113:
        if struct.unpack("!H", pkt[14:16])[0] != 0x0800:
            continue
        ip = pkt[16:]
    else:
        sys.exit(f"unsupported linktype {linktype}")
    if ip[9] != 6:
        continue
    ihl = (ip[0] & 15) * 4
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    tcp = ip[ihl:]
    sport, dport, seq, ack, offflags = struct.unpack("!HHIIH", tcp[:14])
    doff = (offflags >> 12) * 4
    flags = offflags & 0x3F
    payload = struct.unpack('!H', ip[2:4])[0] - ihl - doff
    opts, toa, kinds = tcp[20:doff], None, []
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        length = opts[i + 1]
        kinds.append(kind)
        if kind == 254 and length == 8:
            port = struct.unpack("!H", opts[i + 2:i + 4])[0]
            toa = f"{socket.inet_ntoa(opts[i + 4:i + 8])}:{port}"
        i += max(length, 2)
    names = "".join(n for n, b in zip("FSRPAU", range(6)) if flags & (1 << b))
    print(f"{src}:{sport}>{dst}:{dport} [{names}] len={payload} opts={kinds} toa={toa}")

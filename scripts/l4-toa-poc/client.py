#!/usr/bin/env python3
# client.py <host> <port> peer|bulk <n>|hold <fifo>
import hashlib, os, socket, sys

host, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
family = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(family, socket.SOCK_STREAM)
s.connect((host, port))
f = s.makefile("rwb")
local = s.getsockname()
if mode == "peer":
    f.write(b"PEER\n"); f.flush()
    print(f"client={local[0]}:{local[1]} origin_saw={f.readline().decode().strip()}")
elif mode == "bulk":
    n = int(sys.argv[4])
    data = os.urandom(n)
    f.write(f"BULK {n}\n".encode() + data); f.flush()
    got = f.readline().decode().strip()
    print(f"bulk {n} match={got == hashlib.sha256(data).hexdigest()}")
else:
    f.write(b"HOLD\n"); f.flush()
    f.readline()
    print(f"held client={local[0]}:{local[1]}", flush=True)
    open(sys.argv[4]).read()  # block until the test writes to the fifo
    f.write(b"PEER\n"); f.flush()
    print(f"after-attach origin_saw={f.readline().decode().strip()}")

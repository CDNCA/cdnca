#!/usr/bin/env python3
# Origin used by the TOA PoC. Line protocol per connection:
#   "PEER\n"        -> replies "<getpeername ip>:<port>\n"
#   "BULK <n>\n"    -> reads n bytes, replies "<sha256>\n"
#   "HOLD\n"        -> replies "held\n", waits for one more line, replies peer
import hashlib, socket, socketserver, sys


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.decode().strip().split()
            peer = self.connection.getpeername()
            if cmd[0] == "PEER":
                self.wfile.write(f"{peer[0]}:{peer[1]}\n".encode())
            elif cmd[0] == "BULK":
                n = int(cmd[1])
                h = hashlib.sha256()
                while n:
                    chunk = self.rfile.read(min(n, 65536))
                    if not chunk:
                        return
                    h.update(chunk)
                    n -= len(chunk)
                self.wfile.write((h.hexdigest() + "\n").encode())
            else:
                self.wfile.write(b"held\n")
            self.wfile.flush()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


Server(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()

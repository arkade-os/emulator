#!/usr/bin/env python3
"""Heartbeat responder for Nitro Enclave init.

The EIF init binary connects to vsock CID 3 port 9000, sends byte 0xB7,
and expects 0xB7 back. In QEMU emulation with forward-cid=1,
vhost-device-vsock forwards this to the host's AF_VSOCK loopback.

This script listens on AF_VSOCK port 9000 and echoes the heartbeat byte.
"""

import socket
import sys

VMADDR_CID_ANY = 0xFFFFFFFF  # -1 as unsigned 32-bit
HEARTBEAT_PORT = 9000
HEARTBEAT_BYTE = b'\xb7'

def main():
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((VMADDR_CID_ANY, HEARTBEAT_PORT))
    sock.listen(1)
    print(f"Heartbeat: listening on vsock port {HEARTBEAT_PORT}", flush=True)

    while True:
        try:
            conn, (cid, port) = sock.accept()
            data = conn.recv(1)
            if data:
                conn.send(data)
            conn.close()
            print(f"Heartbeat: OK (CID {cid}, sent {data.hex()})", flush=True)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Heartbeat: error: {e}", file=sys.stderr, flush=True)

    sock.close()

if __name__ == '__main__':
    main()

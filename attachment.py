import argparse
import hashlib
import json
import os
import secrets
import socketserver
import sys


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

FLAG = "IONIC{H1d03P_TR1}"


def point_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result



class ChronosNonceEngine:
    def __init__(self, master_secret: int):
        self._master_secret = master_secret.to_bytes(32, "big")
        raw = bytearray(os.urandom(32))
        raw[0] &= 0x7F
        if raw[0] == 0:
            raw[0] = 0x42
        self._register = raw
        self._counter = 0

    def next_nonce(self, msg: bytes) -> int:
        self._counter += 1
        entropy = hashlib.sha256(
            self._master_secret
            + bytes(self._register)
            + self._counter.to_bytes(4, "big")
            + msg
        ).digest()

        self._register[20:32] = entropy[:12]
        return int.from_bytes(self._register, "big")


class ChronosHSMSession:
    MAX_QUOTA = 5

    def __init__(self):
        self.d = secrets.randbelow(N - 2) + 1
        self.Q = scalar_mult(self.d, G)
        self.nonce_engine = ChronosNonceEngine(self.d)
        self.quota_used = 0
        self.admin_token = secrets.token_hex(16)
        self.target_cmd = f"UNLOCK_MASTER_VAULT:{self.admin_token}".encode()

    def hash_msg(self, msg: bytes) -> int:
        return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N

    def sign(self, msg: bytes):
        z = self.hash_msg(msg)
        while True:
            k = self.nonce_engine.next_nonce(msg)
            R = scalar_mult(k, G)
            r = R[0] % N
            if r == 0:
                continue
            s = (pow(k, -1, N) * (z + r * self.d)) % N
            if s != 0:
                return (r, s)

    def verify(self, msg: bytes, r: int, s: int) -> bool:
        if not (1 <= r < N and 1 <= s < N):
            return False
        z = self.hash_msg(msg)
        w = pow(s, -1, N)
        u1 = (z * w) % N
        u2 = (r * w) % N
        pt = point_add(scalar_mult(u1, G), scalar_mult(u2, self.Q))
        if pt is None:
            return False
        return (pt[0] % N) == r


BANNER = r"""
==========================================================
THE     *        .       *        .        *       .
____ _____ _____ _     _        _    ____      *
/ ___|_   _| ____| |   | |      / \  |  _ \   .       *
\___ \ | | |  _| | |   | |     / _ \ | |_) |     .
___)  || | | |___| |___| |___ / ___ \|  _ <   *         .
|____/ |_| |_____|_____|_____/_/   \_\_| \_\
.               *                            .       *
     .   *       .     S U B T R A C T I O N    *
==========================================================
"""


def handle_session(rfile, wfile):
    def send(text: str):
        wfile.write((text + "\n").encode())
        wfile.flush()

    session = ChronosHSMSession()
    send(BANNER.strip())
    send("[*] Session initialized. Curve: secp256k1")
    send(f"[*] Public Key Qx : {hex(session.Q[0])}")
    send(f"[*] Public Key Qy : {hex(session.Q[1])}")
    send(f"[*] Vault Target  : {session.target_cmd.decode()}")
    send(f"[*] Signing Quota : {session.MAX_QUOTA} audit messages per session\n")

    while True:
        send("Menu:")
        send("  [1] Sign audit message (hex)")
        send("  [2] Unlock Master Vault (submit admin signature)")
        send("  [3] Show session info")
        send("  [4] Exit")
        wfile.write(b"> ")
        wfile.flush()

        line = rfile.readline()
        if not line:
            break
        choice = line.decode(errors="ignore").strip()

        if choice == "1":
            if session.quota_used >= session.MAX_QUOTA:
                send("[-] Error: Audit signing quota exhausted for this session.")
                continue
            wfile.write(b"Enter message in hex: ")
            wfile.flush()
            msg_line = rfile.readline()
            if not msg_line:
                break
            try:
                msg = bytes.fromhex(msg_line.decode(errors="ignore").strip())
            except ValueError:
                send("[-] Error: Invalid hex string.")
                continue

            if len(msg) == 0 or len(msg) > 256:
                send("[-] Error: Message must be between 1 and 256 bytes.")
                continue

            if b"UNLOCK_MASTER_VAULT" in msg:
                send("[-] Security Alert: Restricted command rejected by policy filter!")
                continue

            session.quota_used += 1
            r, s = session.sign(msg)
            z = session.hash_msg(msg)
            resp = {
                "quota_remaining": session.MAX_QUOTA - session.quota_used,
                "z": hex(z),
                "r": hex(r),
                "s": hex(s),
            }
            send("[+] Signature generated: " + json.dumps(resp))

        elif choice == "2":
            wfile.write(b"Enter signature r (hex or int): ")
            wfile.flush()
            r_line = rfile.readline()
            wfile.write(b"Enter signature s (hex or int): ")
            wfile.flush()
            s_line = rfile.readline()
            if not r_line or not s_line:
                break
            try:
                r_val = int(r_line.decode(errors="ignore").strip(), 0)
                s_val = int(s_line.decode(errors="ignore").strip(), 0)
            except ValueError:
                send("[-] Error: Invalid integer format.")
                continue

            if session.verify(session.target_cmd, r_val, s_val):
                send(f"[+] Master Vault Unlocked! Here is your flag: {FLAG}")
                break
            else:
                send("[-] Error: Invalid ECDSA signature for Vault Target!")

        elif choice == "3":
            info = {
                "Qx": hex(session.Q[0]),
                "Qy": hex(session.Q[1]),
                "target_command": session.target_cmd.decode(),
                "quota_remaining": session.MAX_QUOTA - session.quota_used,
            }
            send("[*] Session Info: " + json.dumps(info))

        elif choice == "4":
            send("Goodbye.")
            break
        else:
            send("[-] Invalid option.")


class ThreadedTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(60.0)
        try:
            handle_session(self.rfile, self.wfile)
        except Exception:
            pass


class ReusableThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description="Chronos HSM Vault CTF Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=1337, help="Bind port (default: 1337)")
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Run over stdin/stdout",
    )
    args = parser.parse_args()

    if args.stdio:
        handle_session(sys.stdin.buffer, sys.stdout.buffer)
    else:
        with ReusableThreadedTCPServer((args.host, args.port), ThreadedTCPHandler) as server:
            print(f"[*] Chronos HSM Vault listening on {args.host}:{args.port} ...", flush=True)
            server.serve_forever()


if __name__ == "__main__":
    main()

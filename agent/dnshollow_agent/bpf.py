"""Kernel packet filter: only DNS (UDP/TCP port 53, IPv4 + IPv6) reaches Python.

The agent opens an AF_PACKET / SOCK_DGRAM socket, so packets start at the IP
header (the kernel removes the Ethernet / VPN link header for us). That makes
one filter work on every interface type.

The program is built with a tiny assembler so jump offsets are never
hand-counted. tests/test_agent_bpf.py runs it in a BPF interpreter.
"""
import ctypes
import socket

# classic BPF opcodes
LDB_ABS, LDH_ABS, LDH_IND, LDXB_MSH = 0x30, 0x28, 0x48, 0xB1
AND_K, JEQ_K, JSET_K, RET_K = 0x54, 0x15, 0x45, 0x06
ACCEPT_BYTES = 262144
SO_ATTACH_FILTER = getattr(socket, "SO_ATTACH_FILTER", 26)

# (label, op, k, jump_true, jump_false)  jumps are label names or None (= next)
_PROGRAM = [
    (None,     "ldb",  0,      None,    None),
    (None,     "and",  0xF0,   None,    None),
    (None,     "jeq",  0x40,   "v4",    "chk6"),
    ("chk6",   "jeq",  0x60,   "v6",    "drop"),
    ("v4",     "ldh",  6,      None,    None),                 # flags + fragment offset
    (None,     "jset", 0x1FFF, "drop",  None),                 # not the first fragment -> drop
    (None,     "ldb",  9,      None,    None),                 # protocol
    (None,     "jeq",  17,     "v4p",   "v4tcp"),
    ("v4tcp",  "jeq",  6,      "v4p",   "drop"),
    ("v4p",    "ldxb", 0,      None,    None),                 # X = header length
    (None,     "ldhx", 0,      None,    None),                 # source port
    (None,     "jeq",  53,     "ok",    None),
    (None,     "ldhx", 2,      None,    None),                 # destination port
    (None,     "jeq",  53,     "ok",    "drop"),
    ("v6",     "ldb",  6,      None,    None),                 # next header
    (None,     "jeq",  17,     "v6p",   "v6tcp"),
    ("v6tcp",  "jeq",  6,      "v6p",   "drop"),
    ("v6p",    "ldh",  40,     None,    None),
    (None,     "jeq",  53,     "ok",    None),
    (None,     "ldh",  42,     None,    None),
    (None,     "jeq",  53,     "ok",    "drop"),
    ("ok",     "ret",  ACCEPT_BYTES, None, None),
    ("drop",   "ret",  0,      None,    None),
]
_CODES = {"ldb": LDB_ABS, "ldh": LDH_ABS, "ldhx": LDH_IND, "ldxb": LDXB_MSH,
          "and": AND_K, "jeq": JEQ_K, "jset": JSET_K, "ret": RET_K}


def assemble():
    """-> list of (code, jt, jf, k)."""
    labels = {lab: i for i, (lab, *_rest) in enumerate(_PROGRAM) if lab}
    out = []
    for i, (_lab, op, k, jt, jf) in enumerate(_PROGRAM):
        if op in ("jeq", "jset"):
            t = labels[jt] - i - 1 if jt else 0
            f = labels[jf] - i - 1 if jf else 0
            assert 0 <= t <= 255 and 0 <= f <= 255
            out.append((_CODES[op], t, f, k))
        else:
            out.append((_CODES[op], 0, 0, k))
    return out


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]


def attach(sock) -> None:
    prog = assemble()
    arr = (_SockFilter * len(prog))(*[_SockFilter(*ins) for ins in prog])
    fprog = _SockFprog(len(prog), arr)
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bytes(fprog))

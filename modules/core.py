"""
core.py - Keccak256, CBOR decoder, disassembler, entropy
"""

import struct, re, math, collections
from .constants import OPCODES

# ─────────────────────────────────────────────────────────────────────────────
#  PURE-PYTHON KECCAK-256
# ─────────────────────────────────────────────────────────────────────────────
_KRC = [
    0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
    0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
    0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
    0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
    0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
    0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008,
]
_ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]

def keccak256(data: bytes) -> bytes:
    rb = 136
    msg = bytearray(data)
    msg += b'\x01'
    while len(msg) % rb: msg += b'\x00'
    msg[-1] |= 0x80
    S = [[0]*5 for _ in range(5)]
    def r64(x,n): return ((x<<n)|(x>>(64-n)))&0xFFFFFFFFFFFFFFFF
    def kf(S):
        for rnd in range(24):
            C=[S[x][0]^S[x][1]^S[x][2]^S[x][3]^S[x][4] for x in range(5)]
            D=[C[(x-1)%5]^r64(C[(x+1)%5],1) for x in range(5)]
            S=[[S[x][y]^D[x] for y in range(5)] for x in range(5)]
            B=[[0]*5 for _ in range(5)]
            for x in range(5):
                for y in range(5): B[y][(2*x+3*y)%5]=r64(S[x][y],_ROT[x][y])
            S=[[B[x][y]^((~B[(x+1)%5][y])&B[(x+2)%5][y]) for y in range(5)] for x in range(5)]
            S[0][0]^=_KRC[rnd]
        return S
    for bs in range(0,len(msg),rb):
        lanes=struct.unpack_from('<'+'Q'*(rb//8),msg,bs)
        i=0
        for y in range(5):
            for x in range(5):
                if i<len(lanes): S[x][y]^=lanes[i]; i+=1
        S=kf(S)
    out=b''
    for y in range(5):
        for x in range(5): out+=struct.pack('<Q',S[x][y])
    return out[:32]

def keccak4(sig: str) -> str:
    return keccak256(sig.encode()).hex()[:8]

# ─────────────────────────────────────────────────────────────────────────────
#  BASE58 ENCODER (for IPFS CID)
# ─────────────────────────────────────────────────────────────────────────────
_B58A = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(data):
    n = int.from_bytes(data,"big"); r=[]
    while n: n,rem=divmod(n,58); r.append(_B58A[rem:rem+1])
    lz = len(data)-len(data.lstrip(b"\x00"))
    return (b"1"*lz + b"".join(reversed(r))).decode()

# ─────────────────────────────────────────────────────────────────────────────
#  CBOR METADATA DECODER
# ─────────────────────────────────────────────────────────────────────────────
def decode_cbor(code):
    if len(code) < 4: return {}
    clen = struct.unpack(">H", code[-2:])[0]
    if clen == 0 or clen > len(code)-2: return {}
    blk  = code[-(clen+2):-2]
    res  = {"cbor_len": clen, "cbor_offset": len(code)-clen-2}
    try:
        p = 0
        if p >= len(blk): return res
        hdr = blk[p]; p += 1
        if (hdr & 0xe0) != 0xa0: return res
        n_pairs = hdr & 0x1f

        def read_item(data, pos):
            if pos >= len(data): return None, pos
            b = data[pos]; pos += 1
            maj = (b & 0xe0) >> 5; info = b & 0x1f
            if   info < 24:  val = info
            elif info == 24: val = data[pos]; pos += 1
            elif info == 25: val = struct.unpack(">H",data[pos:pos+2])[0]; pos += 2
            elif info == 26: val = struct.unpack(">I",data[pos:pos+4])[0]; pos += 4
            else:            return None, pos
            if maj == 2:
                item=data[pos:pos+val]; pos+=val; return item, pos
            elif maj == 3:
                item=data[pos:pos+val].decode("utf-8","replace"); pos+=val; return item, pos
            elif maj == 0: return val, pos
            elif maj == 7:
                if b == 0xf5: return True, pos
                if b == 0xf4: return False, pos
            return None, pos

        for _ in range(n_pairs):
            key, p = read_item(blk, p)
            val, p = read_item(blk, p)
            if key is None: break
            k = key if isinstance(key,str) else key.decode("utf-8","replace")
            if k == "solc" and isinstance(val,(bytes,bytearray)) and len(val)==3:
                res["solc"] = f"{val[0]}.{val[1]}.{val[2]}"
            elif k == "ipfs" and isinstance(val,(bytes,bytearray)) and len(val)==32:
                res["ipfs_hex"] = val.hex()
                res["ipfs_cid"] = b58(bytes([0x12,0x20])+bytes(val))
            elif k in ("bzzr0","bzzr1") and isinstance(val,(bytes,bytearray)):
                res[k] = val.hex()
            elif k == "experimental":
                res["experimental"] = bool(val)
            else:
                res[k] = repr(val)
    except Exception as e:
        res["parse_error"] = str(e)
    return res

# ─────────────────────────────────────────────────────────────────────────────
#  DISASSEMBLER
# ─────────────────────────────────────────────────────────────────────────────
def disassemble(code):
    out = []; i = 0
    while i < len(code):
        op = code[i]
        mnem,gas,_,_,cat = OPCODES.get(op, (f"UNKNOWN(0x{op:02x})",0,0,0,"unknown"))
        if 0x60 <= op <= 0x7f:
            sz = op - 0x5f; operand = code[i+1:i+1+sz]
            out.append((i,op,mnem,operand,gas,cat)); i += 1+sz
        else:
            out.append((i,op,mnem,b"",gas,cat)); i += 1
    return out

# ─────────────────────────────────────────────────────────────────────────────
#  ENTROPY
# ─────────────────────────────────────────────────────────────────────────────
def entropy(data):
    if not data: return 0.0
    c=collections.Counter(data); t=len(data)
    return -sum((v/t)*math.log2(v/t) for v in c.values())

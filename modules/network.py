"""
network.py - RPC calls, chain detection, storage slot reading
"""

import json, re, urllib.request
from .constants import CHAINS, PROXY_SLOTS

# ─────────────────────────────────────────────────────────────────────────────
#  LOW-LEVEL RPC
# ─────────────────────────────────────────────────────────────────────────────
def rpc_call(url, method, params, timeout=7):
    try:
        d = json.dumps({"jsonrpc":"2.0","method":method,"params":params,"id":1}).encode()
        req = urllib.request.Request(url, data=d,
              headers={"Content-Type":"application/json","User-Agent":"evmanalyzer/8"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res = json.loads(r.read())
            return res.get("result") if res and "result" in res else None
    except:
        return None

def http_get_json(url, timeout=7):
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"evmanalyzer/8"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except:
        return None

# ─────────────────────────────────────────────────────────────────────────────
#  CHAIN / RPC INIT
# ─────────────────────────────────────────────────────────────────────────────
class ChainConnection:
    def __init__(self, custom_rpc=None, chain_id_force=None, contract_addr=None, no_net=False):
        self.custom_rpc = custom_rpc
        self.chain_id_force = chain_id_force
        self.contract_addr = contract_addr
        self.no_net = no_net
        self.active_rpc = None
        self.active_chain = None
        self.meta = {}

    def init(self):
        if self.no_net:
            return False
        cands = []
        if self.custom_rpc:
            cands = [(self.custom_rpc, None)]
        if self.chain_id_force and self.chain_id_force in CHAINS:
            cands += [(u, self.chain_id_force) for u in CHAINS[self.chain_id_force]["rpcs"]]
        if not cands:
            for cid, info in CHAINS.items():
                cands += [(info["rpcs"][0], cid)]
        for url, hint in cands:
            cr = rpc_call(url, "eth_chainId", [])
            if not cr: continue
            cid = int(cr, 16)
            if hint and cid != hint: continue
            if self.contract_addr:
                code = rpc_call(url, "eth_getCode", [self.contract_addr, "latest"])
                if not code or len(code) <= 4: continue
            self.active_rpc = url
            self.active_chain = cid
            return True
        return False

    @property
    def chain_info(self):
        return CHAINS.get(self.active_chain, {})

    @property
    def symbol(self):
        return self.chain_info.get("symbol", "tokens")

    def get_balance(self, addr):
        bal = rpc_call(self.active_rpc, "eth_getBalance", [addr, "latest"])
        if bal:
            return f"{int(bal,16)/1e18:.6f} {self.symbol}"
        return None

    def get_code(self, addr):
        return rpc_call(self.active_rpc, "eth_getCode", [addr, "latest"])

    def get_nonce(self, addr):
        n = rpc_call(self.active_rpc, "eth_getTransactionCount", [addr, "latest"])
        return int(n, 16) if n else None

    def get_storage_at(self, addr, slot):
        sp = "0x" + slot.replace("0x","").zfill(64)
        return rpc_call(self.active_rpc, "eth_getStorageAt", [addr, sp, "latest"])

    def read_proxy_slots(self, addr):
        proxy_info = {}
        for slot, label in PROXY_SLOTS.items():
            v = self.get_storage_at(addr, slot)
            if v and v != "0x" + "0"*64:
                a = "0x" + v[-40:]
                if a != "0x" + "0"*40:
                    proxy_info[label] = a
        return proxy_info

    def read_storage_slots(self, addr, evmole_stor):
        fetched = 0
        for rec in evmole_stor:
            v = self.get_storage_at(addr, rec["slot_hex"])
            if v:
                rec["live_value"] = v
                rec["decoded"] = decode_slot(v, rec["type"], rec["offset"], self.symbol)
                fetched += 1
        return fetched


def decode_slot(raw, typ, offset=0, symbol="tokens"):
    """Decode raw 32-byte storage slot value into human-readable form."""
    if not raw or raw == "0x"+"0"*64: return "0x0 (empty/unset)"
    val = raw.replace("0x","").lower().zfill(64); t = (typ or "").lower()
    try:
        if "address" in t:
            a = "0x" + val[-40:]
            return a if a != "0x"+"0"*40 else "0x0 (zero address)"
        if "bool" in t:
            return "true" if val[-2:] == "01" else "false"
        if "uint" in t:
            bits = 256; m = re.search(r'uint(\d+)', t)
            if m: bits = int(m.group(1))
            bs = bits // 8
            start_nibble = 64 - (offset+bs)*2
            end_nibble   = 64 - offset*2
            seg = val[max(0,start_nibble):end_nibble]
            if not seg.strip("0"): return "0 (empty)"
            num = int(seg, 16) if seg else 0
            return f"{num} ({num/1e18:.6f} {symbol})" if num > 10**15 else str(num)
        if "bytes" in t:
            s = val.rstrip("0")
            try:
                dec = bytes.fromhex(s).decode("utf-8")
                if dec.isprintable() and dec.strip(): return f'"{dec}"'
            except: pass
            return "0x" + (s or "0")
        return "0x" + (val.lstrip("0") or "0")
    except: return raw

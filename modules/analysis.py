"""
analysis.py - Selector lookup, classification, events, CFG, vulns, stats, strings
"""

import json, re, collections, urllib.request
from pathlib import Path
from .constants import (BUILTIN_SELECTORS, ERC_IFACE, KNOWN_EVENTS, KNOWN_4BYTE_ERRORS,
                         SOURCIFY_PARQUET_DIR)
from .core import keccak256

# ─────────────────────────────────────────────────────────────────────────────
#  PARQUET SIGNATURE DATABASE
# ─────────────────────────────────────────────────────────────────────────────
_parquet_cache: dict = {}
_parquet_loaded: bool = False
_parquet_available: bool = False
_parquet_file_count: int = 0

def _normalize_selector(sel_raw):
    if sel_raw is None:
        return None
    if isinstance(sel_raw, (bytes, bytearray)):
        if len(sel_raw) != 4: return None
        return sel_raw.hex()
    if isinstance(sel_raw, int):
        return f"{sel_raw & 0xffffffff:08x}"
    s = str(sel_raw).strip().strip("'\"").lower()
    if s.startswith("0x"): s = s[2:]
    if len(s) != 8 or any(c not in "0123456789abcdef" for c in s):
        return None
    return s

def load_parquet_db(verbose=False):
    global _parquet_loaded, _parquet_available, _parquet_file_count
    if _parquet_loaded: return
    _parquet_loaded = True
    sig_dir = Path(SOURCIFY_PARQUET_DIR)
    if not sig_dir.is_dir():
        if verbose: print(f"  \033[93m[parquet] directory not found: {sig_dir}\033[0m")
        return
    try:
        import pyarrow.parquet as pq
    except ImportError:
        if verbose: print(f"  \033[93m[parquet] pyarrow not installed\033[0m")
        return
    files = sorted(sig_dir.glob("*.parquet"),
                   key=lambda p: (0 if p.name.startswith("v1_") else 1, p.name),
                   reverse=True)
    if not files:
        if verbose: print(f"  \033[93m[parquet] no *.parquet files in {sig_dir}\033[0m")
        return
    _parquet_file_count = len(files)
    rows_seen = 0; rows_kept = 0
    for pf in files:
        try:
            tbl = pq.read_table(str(pf), columns=None)
            sel_candidates = ("signature_hash_4", "hex_signature", "selector",
                               "function_selector", "hash", "hash4", "sel")
            sig_candidates = ("signature", "text_signature", "name",
                               "function_signature", "sig")
            names_lower = {c.lower(): c for c in tbl.schema.names}
            sel_col = next((names_lower[c] for c in sel_candidates if c in names_lower), None)
            sig_col = next((names_lower[c] for c in sig_candidates if c in names_lower), None)
            if not sel_col or not sig_col:
                if verbose: print(f"  \033[93m[parquet] {pf.name}: no matching columns\033[0m")
                continue
            sels = tbl.column(sel_col).to_pylist()
            sigs = tbl.column(sig_col).to_pylist()
            file_kept = 0
            for sel_raw, sig in zip(sels, sigs):
                rows_seen += 1
                if sig is None: continue
                sel_str = _normalize_selector(sel_raw)
                if sel_str is None: continue
                sig_str = str(sig).strip()
                if not sig_str: continue
                bucket = _parquet_cache.setdefault(sel_str, [])
                if sig_str not in bucket:
                    bucket.append(sig_str)
                file_kept += 1; rows_kept += 1
            if verbose:
                print(f"  \033[2m[parquet] {pf.name}: {file_kept:,} rows kept\033[0m")
        except Exception as e:
            if verbose: print(f"  \033[91m[parquet] {pf.name}: failed — {e}\033[0m")
            continue
    _parquet_available = bool(_parquet_cache)
    if verbose:
        print(f"  \033[2m[parquet] total: {rows_seen:,} scanned, {rows_kept:,} kept, "
              f"{len(_parquet_cache):,} unique selectors\033[0m")

def lookup_parquet(sel):
    load_parquet_db()
    hits = _parquet_cache.get(sel.lower())
    return hits if hits else None


# ─────────────────────────────────────────────────────────────────────────────
#  SELECTOR LOOKUP  (builtin → local-db → parquet → sourcify-api → 4byte)
# ─────────────────────────────────────────────────────────────────────────────
def _to_list(v):
    if v is None: return None
    if isinstance(v,str): return [v]
    if isinstance(v,(list,tuple)): return [str(s) for s in v if isinstance(s,str)] or None
    if isinstance(v,dict):
        flat=[]
        for x in v.values(): flat.extend(_to_list(x) or [])
        return flat or None
    return None

def lookup_local(sel, local_db):
    return _to_list(local_db.get(sel))

def lookup_sourcify_api(sel, no_net=False):
    if no_net: return None
    d = None
    try:
        url = f"https://api.4byte.sourcify.dev/signature-database/v1/lookup?function=0x{sel}"
        req = urllib.request.Request(url, headers={"User-Agent":"evmanalyzer/8"})
        with urllib.request.urlopen(req, timeout=7) as r:
            d = json.loads(r.read())
    except: pass
    if not d or not d.get("ok"): return None
    fb = d.get("result",{}).get("function",{})
    if isinstance(fb, dict):
        s = fb.get(f"0x{sel}") or fb.get(sel)
        if not s and fb: s = next(iter(fb.values()), None)
    else: s = fb
    return _to_list(s)

def lookup_4byte(sel, no_net=False):
    if no_net: return None
    d = None
    try:
        url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature=0x{sel}&format=json"
        req = urllib.request.Request(url, headers={"User-Agent":"evmanalyzer/8"})
        with urllib.request.urlopen(req, timeout=7) as r:
            d = json.loads(r.read())
    except: pass
    if not d: return None
    return [r["text_signature"] for r in sorted(d.get("results",[]), key=lambda x:x.get("id",9999))
            if isinstance(r.get("text_signature"),str)] or None

def best_match(sigs, args):
    if not sigs: return None
    if args:
        for s in sigs:
            if isinstance(s,str) and s[s.find("(")+1:s.rfind(")")]==args: return s
    return sigs[0]

# Known mutability overrides (evmole sometimes returns 'pure' for nonpayable/view)
_MUTABILITY_OVERRIDE = {
    "23b872dd": "nonpayable",  # transferFrom
    "a9059cbb": "nonpayable",  # transfer
    "095ea7b3": "nonpayable",  # approve
    "a22cb465": "nonpayable",  # setApprovalForAll
    "42842e0e": "nonpayable",  # safeTransferFrom (ERC721)
    "f242432a": "nonpayable",  # safeTransferFrom (ERC1155)
    "2eb2c2d6": "nonpayable",  # safeBatchTransferFrom
    "8456cb59": "nonpayable",  # pause
    "3f4ba83a": "nonpayable",  # unpause
    "f2fde38b": "nonpayable",  # transferOwnership
    "715018a6": "nonpayable",  # renounceOwnership
    "2f2ff15d": "nonpayable",  # grantRole
    "d547741f": "nonpayable",  # revokeRole
    "36568abe": "nonpayable",  # renounceRole
    "6a627842": "nonpayable",  # mint (UniV2)
    "89afcb44": "nonpayable",  # burn (UniV2)
    "022c0d9f": "nonpayable",  # swap (UniV2)
    "a9059cbb": "nonpayable",  # transfer
    "23b872dd": "nonpayable",  # transferFrom
}


def resolve_selectors(evmole_fns, local_db, no_net=False):
    """Resolve all selectors through the lookup chain."""
    abi_results = []
    found_selectors = set()
    for fn in evmole_fns:
        sel, args, mut, off = fn["selector"], fn["arguments"], fn["state_mutability"], fn["bytecode_offset"]
        found_selectors.add(sel)
        if sel in BUILTIN_SELECTORS:
            sig, src = BUILTIN_SELECTORS[sel]
            sigs = [sig]
        else:
            sigs = lookup_local(sel, local_db);        src = "local-db"          if sigs else None
            if not sigs: sigs = lookup_parquet(sel);    src = "sourcify-parquet"  if sigs else None
            if not sigs: sigs = lookup_sourcify_api(sel, no_net); src = "sourcify-api" if sigs else None
            if not sigs: sigs = lookup_4byte(sel, no_net);       src = "4byte.directory" if sigs else "unknown"
        
        # Override mutability if evmole got it wrong
        if sel in _MUTABILITY_OVERRIDE:
            override = _MUTABILITY_OVERRIDE[sel]
            if mut == "pure" and override != "pure":
                mut = override
        
        abi_results.append({
            "selector":sel, "signature":best_match(sigs, args),
            "all_signatures":sigs or [], "arguments":args,
            "state_mutability":mut, "bytecode_offset":off, "source":src
        })
    return abi_results, found_selectors


# ─────────────────────────────────────────────────────────────────────────────
#  CONTRACT CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────────────
def classify(sel_set):
    req = collections.defaultdict(list)
    opt = collections.defaultdict(list)
    for sel,(std,_,required) in ERC_IFACE.items():
        (req if required else opt)[std].append(sel)
    out = []
    for std, reqs in req.items():
        matched  = [s for s in reqs if s in sel_set]
        optional = [s for s in opt.get(std,[]) if s in sel_set]
        pct = len(matched)/len(reqs)*100 if reqs else 0
        if pct >= 50:
            out.append({"standard":std,"pct":pct,"matched":matched,"required":reqs,"optional":optional})
    out.sort(key=lambda x:-x["pct"])
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  EVENT EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────
def extract_events(instrs, no_net=False):
    LOG_OPS = {0xa0,0xa1,0xa2,0xa3,0xa4}
    seen = set(); out = []
    unknown_topics = []
    
    for idx,(pc,op,mnem,operand,gas,cat) in enumerate(instrs):
        if op in LOG_OPS:
            for j in range(idx-1, max(idx-20,0), -1):
                jpc,jop,jm,joper,*_ = instrs[j]
                if jop == 0x7f and len(joper)==32:
                    topic = joper.hex()
                    if topic not in seen:
                        seen.add(topic)
                        known = KNOWN_EVENTS.get(topic)
                        if known:
                            out.append({"topic":topic,"signature":known,"log_op":mnem,"pc":jpc})
                        else:
                            out.append({"topic":topic,"signature":"<unknown>","log_op":mnem,"pc":jpc})
                            unknown_topics.append(topic)
    
    # Lookup unknown topics via 4byte.directory API
    if unknown_topics and not no_net:
        for topic in unknown_topics:
            sig = _lookup_event_4byte(topic)
            if sig:
                for e in out:
                    if e["topic"] == topic:
                        e["signature"] = sig
    
    return out


def _lookup_event_4byte(topic):
    """Lookup event topic signature via 4byte.directory API."""
    try:
        url = f"https://www.4byte.directory/api/v1/event-signatures/?hex_signature=0x{topic}&format=json"
        req = urllib.request.Request(url, headers={"User-Agent":"bytezorth/1"})
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read())
            results = d.get("results", [])
            if results:
                # Sort by id (lowest = most common)
                results.sort(key=lambda x: x.get("id", 9999))
                return results[0].get("text_signature", "")
    except: pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  CFG  (basic blocks + loop detection)
# ─────────────────────────────────────────────────────────────────────────────
TERMINATORS = {0x00,0x56,0x57,0xf3,0xfd,0xfe,0xff}

def build_cfg(instrs):
    jumpdests = {pc for pc,op,*_ in instrs if op == 0x5b}
    blocks = {}; cur_start = instrs[0][0] if instrs else 0; cur = []
    def flush():
        nonlocal cur_start, cur
        if cur:
            blocks[cur_start] = {"start":cur_start,"instrs":cur[:],"end_op":cur[-1][2],
                                  "successors":[],"predecessors":[]}
        cur = []
    for idx,(pc,op,mnem,operand,gas,cat) in enumerate(instrs):
        if op == 0x5b and cur: flush(); cur_start = pc
        cur.append((pc,op,mnem,operand,gas,cat))
        if op in TERMINATORS or op == 0x57:
            flush()
            if idx+1 < len(instrs): cur_start = instrs[idx+1][0]
    if cur: flush()
    pc_list = sorted(blocks.keys()); pc_idx = {pc:i for i,pc in enumerate(pc_list)}
    for bs, blk in blocks.items():
        li = blk["instrs"]
        if not li: continue
        lpc,lop,lm,loper,*_ = li[-1]
        if lop == 0x57:
            fi = pc_idx.get(bs,-1)+1
            if fi < len(pc_list): blk["successors"].append(pc_list[fi])
            for j in range(len(li)-2,-1,-1):
                pp,pop,pm,poper,*_ = li[j]
                if 0x60 <= pop <= 0x7f and poper:
                    t = int(poper.hex(),16)
                    if t in jumpdests: blk["successors"].append(t)
                    break
        elif lop == 0x56:
            for j in range(len(li)-2,-1,-1):
                pp,pop,pm,poper,*_ = li[j]
                if 0x60 <= pop <= 0x7f and poper:
                    t = int(poper.hex(),16)
                    if t in jumpdests: blk["successors"].append(t)
                    break
        elif lop not in {0x00,0xf3,0xfd,0xfe,0xff}:
            fi = pc_idx.get(bs,-1)+1
            if fi < len(pc_list): blk["successors"].append(pc_list[fi])
    for bs, blk in blocks.items():
        for s in blk["successors"]:
            if s in blocks: blocks[s]["predecessors"].append(bs)
    return blocks, jumpdests


# ─────────────────────────────────────────────────────────────────────────────
#  OPCODE STATS + BYTE ENTROPY
# ─────────────────────────────────────────────────────────────────────────────
def compute_stats(instrs):
    cat_counts  = collections.Counter()
    mnem_counts = collections.Counter()
    total_gas   = 0
    for pc,op,mnem,operand,gas,cat in instrs:
        cat_counts[cat] += 1; mnem_counts[mnem] += 1; total_gas += gas
    return cat_counts, mnem_counts, total_gas


# ─────────────────────────────────────────────────────────────────────────────
#  VULNERABILITY SCANNER  (12 patterns)
# ─────────────────────────────────────────────────────────────────────────────
def scan_vulns(instrs, cfg, found_selectors):
    F = []
    def findop(op_): return [(pc,m) for pc,op,m,*_ in instrs if op==op_]

    sds  = findop(0xff); dcs = findop(0xf4); ccs = findop(0xf2)
    orgs = findop(0x32); tss = findop(0x42); c2s = findop(0xf5)

    # Detect if SafeMath is likely present (Solidity <0.8 with SafeMath)
    _has_safemath = False
    for _, _, mnem, operand, *_ in instrs:
        if len(operand) >= 15:
            try:
                s = operand.decode("utf-8", errors="replace")
                if "SafeMath" in s or "subtraction overflow" in s or "multiplication overflow" in s:
                    _has_safemath = True; break
            except: pass

    for pc,_ in sds:
        F.append({"severity":"HIGH","type":"SELFDESTRUCT","pc":pc,
            "desc":"SELFDESTRUCT present. Contract can be permanently destroyed. "
                   "Ensure caller is restricted to owner only."})
    for pc,_ in dcs:
        blk = next((b for b in cfg.values() if any(i[0]==pc for i in b["instrs"])),None)
        ctrl = blk and any(i[1]==0x35 for i in blk["instrs"])
        sev = "CRITICAL" if ctrl else "MEDIUM"
        F.append({"severity":sev,"type":"DELEGATECALL","pc":pc,
            "desc":f"DELEGATECALL at 0x{pc:04x} executes external code in this contract's storage context."
                   +(" CALLDATALOAD in same block: target address may be caller-controlled." if ctrl else "")})
    for pc,_ in ccs:
        F.append({"severity":"HIGH","type":"CALLCODE_DEPRECATED","pc":pc,
            "desc":f"CALLCODE at 0x{pc:04x} is deprecated. Replace with DELEGATECALL or a direct call."})

    # Reentrancy: CALL before SSTORE in same block
    for blk in cfg.values():
        ops = [i[1] for i in blk["instrs"]]
        if any(op in {0xf1,0xf2} for op in ops) and any(op==0x55 for op in ops):
            call_pc   = next(i[0] for i in blk["instrs"] if i[1] in {0xf1,0xf2})
            sstore_pc = next(i[0] for i in blk["instrs"] if i[1]==0x55)
            if call_pc < sstore_pc:
                F.append({"severity":"HIGH","type":"REENTRANCY","pc":call_pc,
                    "desc":f"CALL at 0x{call_pc:04x} precedes SSTORE at 0x{sstore_pc:04x} in block "
                           f"0x{blk['start']:04x}. State written AFTER external call — classic "
                           "DAO-style reentrancy. Use checks-effects-interactions pattern."})

    for pc,_ in orgs:
        F.append({"severity":"MEDIUM","type":"TX_ORIGIN","pc":pc,
            "desc":f"ORIGIN opcode at 0x{pc:04x}. tx.origin-based access control is vulnerable to phishing."})
    for pc,_ in tss:
        F.append({"severity":"LOW","type":"TIMESTAMP_DEPENDENCY","pc":pc,
            "desc":f"TIMESTAMP at 0x{pc:04x}. Block timestamp can be shifted by miners up to ~15 seconds."})
    for pc,_ in c2s:
        F.append({"severity":"INFO","type":"CREATE2","pc":pc,
            "desc":f"CREATE2 at 0x{pc:04x}. Deploys to a deterministic address."})

    # Unchecked external call return value
    for i_idx,(pc,op,mnem,operand,gas,cat) in enumerate(instrs):
        if op in {0xf1,0xf2,0xfa}:
            pop_found=False; ji_found=False
            for j in range(i_idx+1,min(i_idx+10,len(instrs))):
                jop=instrs[j][1]
                if jop==0x50:  pop_found=True
                if jop==0x57:  ji_found=True; break
                if jop in {0xf1,0xf2,0xfa,0x55}: break
            if pop_found and not ji_found:
                F.append({"severity":"MEDIUM","type":"UNCHECKED_CALL","pc":pc,
                    "desc":f"Return value of CALL at 0x{pc:04x} discarded (POP without JUMPI guard)."})

    # MUL/EXP without overflow guard — skip if SafeMath likely present
    if not _has_safemath:
        for i_idx,(pc,op,mnem,operand,gas,cat) in enumerate(instrs):
            if op in {0x02,0x0a}:
                guard=any(instrs[j][1] in {0xfd,0xfe} for j in range(i_idx+1,min(i_idx+7,len(instrs))))
                if not guard:
                    F.append({"severity":"INFO","type":"POTENTIAL_OVERFLOW","pc":pc,
                        "desc":f"{mnem} at 0x{pc:04x} has no nearby overflow guard."})

    has_cmp = any(op in {0x14,0x10,0x11} for _,op,*_ in instrs)
    if sds and not has_cmp:
        F.append({"severity":"CRITICAL","type":"NO_ACCESS_CONTROL","pc":sds[0][0],
            "desc":"SELFDESTRUCT present with no EQ/LT/GT comparisons detected. "
                   "Contract may have no access control."})

    drain_sel = "abf59fc9"
    if drain_sel in found_selectors:
        F.append({"severity":"MEDIUM","type":"DRAIN_FUNCTION","pc":0,
            "desc":"Function drain(address,address,uint256) [0xabf59fc9] exists. "
                   "Verify it is protected by owner/caller check."})

    sev_order={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    F.sort(key=lambda x: sev_order.get(x["severity"],5))
    return F


# ─────────────────────────────────────────────────────────────────────────────
#  STRING / CONSTANT EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────
def _is_printable_run(data: bytes, min_run: int = 4) -> str | None:
    """
    Return longest printable ASCII run if >= min_run chars.
    Also accepts partial runs if >= 50% of bytes are printable.
    """
    printable = [chr(b) if 32 <= b < 127 else None for b in data]
    best = []; cur = []
    for ch in printable:
        if ch is not None:
            cur.append(ch)
        else:
            if len(cur) > len(best): best = cur
            cur = []
    if len(cur) > len(best): best = cur
    if len(best) >= min_run:
        return "".join(best)
    n_print = sum(1 for b in data if 32 <= b < 127)
    if n_print / max(len(data),1) >= 0.5 and n_print >= min_run:
        return "".join(ch if ch else "." for ch in printable)
    return None


def extract_strings(instrs, min_len=4, min_run=4):
    """
    Extract printable strings from PUSH operands.
    Returns (push_data, four_bytes) where:
      push_data: list of (pc, mnem, text)
      four_bytes: list of (pc, hex, name)
    """
    push_data = []
    four_bytes = []
    for pc, op, mnem, operand, gas, cat in instrs:
        if len(operand) == 4:
            h = operand.hex()
            if h in KNOWN_4BYTE_ERRORS:
                four_bytes.append((pc, h, KNOWN_4BYTE_ERRORS[h]))
            elif h in BUILTIN_SELECTORS:
                four_bytes.append((pc, h, BUILTIN_SELECTORS[h][0]))
        if len(operand) >= min_len:
            text = _is_printable_run(operand, min_run)
            if text and text.strip() not in ("ipfsX","solcC","NH{q","solc","ipfs"):
                push_data.append((pc, mnem, text.strip()))
    return push_data, four_bytes


def stitch_strings(push_data):
    """
    Concatenate adjacent PUSH strings that share a byte boundary.
    If PUSH21 @6795 and PUSH22 @6816 are consecutive and both printable,
    stitch them into a single longer string.
    Returns deduplicated list of (pc, mnem, text).
    """
    if not push_data: return push_data
    
    stitched = []
    i = 0
    while i < len(push_data):
        pc1, mnem1, text1 = push_data[i]
        combined = text1
        j = i + 1
        while j < len(push_data):
            pc2, mnem2, text2 = push_data[j]
            # Check if adjacent: next PUSH starts right after current one
            # PUSH{sz} = 1 byte opcode + sz bytes data, so next pc = pc1 + 1 + sz
            # But we don't have sz here, so check if text2 starts where text1 ends
            if text2 and combined and text2[:3] in combined[-6:]:
                # Overlap detected — merge
                overlap = 0
                for k in range(1, min(len(combined), len(text2))):
                    if text2[:k] in combined:
                        overlap = k
                if overlap > 0:
                    combined = combined + text2[overlap:]
                else:
                    combined = combined + text2
                j += 1
            else:
                break
        stitched.append((pc1, mnem1, combined))
        i = j
    return stitched

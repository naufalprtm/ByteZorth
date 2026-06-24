"""
helpers.py — Shared utility functions for ByteZorth decompiler.

Storage naming, dispatcher extraction, error string detection,
function signature helpers, stub generation, private function detection.
"""

import re, collections
from ..constants import KNOWN_EVENTS


# ─────────────────────────────────────────────────────────────────────────────
#  STORAGE NAMING  (Dedaub-style: infer names from function access patterns)
# ─────────────────────────────────────────────────────────────────────────────
def build_storage_names(contract_classes, evmole_stor, abi_results=None, cfg=None,
                         bytecode_bytes=None, instrs=None):
    stds = {c["standard"] for c in contract_classes}
    
    ERC20 = {
        0: ("_balanceOf", "mapping(address => uint256)"),
        1: ("_allowance", "mapping(address => mapping(address => uint256))"),
        2: ("_totalSupply", "uint256"),
        3: ("_name", "string"),
        4: ("_symbol", "string"),
    }
    
    layout = {}
    if "ERC-20" in stds: layout.update(ERC20)
    
    # Find mapping slots from SHA3 patterns in bytecode
    mapping_slots = set()
    if bytecode_bytes and instrs:
        mapping_slots = _find_mapping_slots_from_bytecode(bytecode_bytes, instrs)
    
    if abi_results and cfg:
        # Build a global slot→function_name map by scanning all SLOADs
        slot_to_fns = collections.defaultdict(set)
        for r in abi_results:
            fn_name = r["signature"]
            if not fn_name: continue
            fn_name_clean = fn_name[:fn_name.index("(")] if "(" in fn_name else fn_name
            off = r.get("bytecode_offset")
            if off is None: continue
            
            slots = _find_sload_slots(off, cfg)
            for s in slots:
                slot_to_fns[s].add(fn_name_clean)
            
            if r.get("state_mutability") in ("view", "pure"):
                params = r.get("arguments", "")
                if not params or params == "":
                    for slot_idx in slots:
                        if slot_idx not in layout and slot_idx < 32:
                            layout[slot_idx] = (f"_{fn_name_clean}", "uint256")
                elif params and "address" in params:
                    for slot_idx in slots:
                        if slot_idx not in layout and slot_idx >= 5:
                            for rec in evmole_stor:
                                try: rec_idx = int(rec["slot_hex"], 16)
                                except: continue
                                if rec_idx == slot_idx and "mapping" in str(rec.get("type","")):
                                    layout[slot_idx] = (f"_{fn_name_clean}", str(rec.get("type","mapping")))
        
        # Fallback: for unmapped mapping slots, try to match by function name
        # that reads them (from the global slot→function map)
        for slot_idx, fn_names in slot_to_fns.items():
            if slot_idx in layout: continue
            if slot_idx < 5: continue  # skip ERC-20 base slots
            # Find the most specific function name (prefer names with "Of", "Times", "ed" suffixes)
            best_name = None
            for fn in fn_names:
                if fn.endswith(("Of", "Times", "ed", "s", "Wait")):
                    best_name = fn; break
            if not best_name and fn_names:
                best_name = next(iter(fn_names))
            if best_name:
                # Find the matching evmole type
                for rec in evmole_stor:
                    try: rec_idx = int(rec["slot_hex"], 16)
                    except: continue
                    if rec_idx == slot_idx:
                        typ = str(rec.get("type", "mapping(address => uint256)"))
                        layout[slot_idx] = (f"_{best_name}", typ)
                        break
    
    # Fallback: for unmapped mapping slots, assign to view functions with address params
    # in the order they appear (most specific function name first)
    if abi_results:
        unmapped = []
        for rec in evmole_stor:
            try: idx = int(rec["slot_hex"], 16)
            except: continue
            if idx not in layout and "mapping" in str(rec.get("type", "")):
                unmapped.append((idx, str(rec.get("type", "mapping(address => uint256)"))))
        unmapped.sort(key=lambda x: x[0])
        
        # Find view functions with address params that aren't already mapped
        view_fns = []
        for r in abi_results:
            if r.get("state_mutability") not in ("view", "pure"): continue
            params = r.get("arguments", "")
            if "address" not in (params or ""): continue
            fn_name = r.get("signature", "")
            if not fn_name: continue
            fn_clean = fn_name[:fn_name.index("(")] if "(" in fn_name else fn_name
            # Skip functions that are already mapped to slots
            if fn_clean in ("name", "symbol", "owner", "balanceOf", "allowance",
                            "totalSupply", "decimals", "paused", "token0", "token1"):
                continue
            view_fns.append(fn_clean)
        
        # Assign unmapped slots to view functions
        for (slot_idx, typ), fn_name in zip(unmapped, view_fns):
            layout[slot_idx] = (f"_{fn_name}", typ)
    
    result = {}
    for rec in evmole_stor:
        sh = rec["slot_hex"]
        try: idx = int(sh, 16)
        except: idx = None
        evmole_type = str(rec.get("type", "")).strip()
        
        if idx is not None and idx in layout:
            name, typ = layout[idx]
            if evmole_type and "mapping" in evmole_type and "mapping" not in typ:
                typ = evmole_type
            if evmole_type and "address" in evmole_type and typ == "uint256":
                typ = evmole_type
            result[sh] = (name, typ)
        elif evmole_type:
            name = f"stor_{idx}" if idx is not None and idx < 32 else f"stor_{sh[-4:]}"
            result[sh] = (name, evmole_type)
        else:
            name = f"stor_{idx}" if idx is not None and idx < 32 else f"stor_{sh[-4:]}"
            result[sh] = (name, "uint256")
    
    return result


def _find_sload_slots(entry_off, cfg):
    """Find storage slot indices accessed by SLOAD in a function."""
    slots = set()
    if entry_off is None: return slots
    entry_block = None
    for bs, blk in cfg.items():
        for pc, *_ in blk["instrs"]:
            if pc == entry_off: entry_block = bs; break
        if entry_block is not None: break
    if entry_block is None: return slots
    
    visited = []; queue = [entry_block]; seen = set()
    while queue and len(visited) < 60:
        cur = queue.pop(0)
        if cur in seen or cur not in cfg: continue
        seen.add(cur); visited.append(cur)
        for s in cfg[cur].get("successors", []):
            if s not in seen: queue.append(s)
    
    for bs in visited:
        if bs not in cfg: continue
        instrs = cfg[bs]["instrs"]
        for i, (pc, op, mnem, operand, gas, cat) in enumerate(instrs):
            if mnem == "SLOAD":
                for j in range(i-1, max(i-5, -1), -1):
                    jop = instrs[j][1]; joperand = instrs[j][3]
                    if 0x60 <= jop <= 0x7f and joperand:
                        try: slots.add(int(joperand.hex(), 16))
                        except: pass
                        break
    return slots


def _find_mapping_slots_from_bytecode(bytecode_bytes, instrs):
    """
    Find mapping storage slots by scanning for SHA3 (keccak256) patterns.
    Mapping access: PUSH <slot> MSTORE ... SHA3 → the slot number is the mapping base.
    Returns set of slot indices that are mapping bases.
    """
    mapping_slots = set()
    if not bytecode_bytes: return mapping_slots
    
    # Find all SHA3 instructions
    sha3_pcs = set()
    for pc, op, mnem, operand, gas, cat in instrs:
        if mnem in ("SHA3", "KECCAK256"):
            sha3_pcs.add(pc)
    
    # For each SHA3, look backward for PUSH values in range 5-20 (typical mapping slots)
    for i, (pc, op, mnem, operand, gas, cat) in enumerate(instrs):
        if mnem not in ("SHA3", "KECCAK256"): continue
        for j in range(i-1, max(i-20, -1), -1):
            jop = instrs[j][1]; joperand = instrs[j][3]
            if 0x60 <= jop <= 0x7f and joperand:
                try:
                    val = int(joperand.hex(), 16)
                    if 5 <= val <= 20 and val != 0x40:  # skip free memory pointer
                        mapping_slots.add(val)
                except: pass
    
    return mapping_slots


# ─────────────────────────────────────────────────────────────────────────────
#  DISPATCHER EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────
def extract_dispatcher(instrs):
    dispatch = {}
    fallback = None
    for i, (pc, op, mnem, operand, gas, cat) in enumerate(instrs):
        if mnem == "CALLDATASIZE" and i+1 < len(instrs) and instrs[i+1][2] == "LT":
            for j in range(i+1, min(i+4, len(instrs))):
                if instrs[j][2] == "JUMPI" and j > 0:
                    prev = instrs[j-1]
                    if prev[2].startswith("PUSH") and prev[3]:
                        try: fallback = int(prev[3].hex(), 16)
                        except: pass
                    break
    for i, (pc, op, mnem, operand, gas, cat) in enumerate(instrs):
        if mnem.startswith("PUSH4") and len(operand) == 4:
            sel_hex = operand.hex()
            for j in range(i+1, min(i+5, len(instrs))):
                jm = instrs[j][2]
                if jm == "EQ":
                    for k in range(j+1, min(j+4, len(instrs))):
                        km = instrs[k][2]
                        if km.startswith("PUSH") and instrs[k][3]:
                            try:
                                dest = int(instrs[k][3].hex(), 16)
                                if dest > 0: dispatch[sel_hex] = dest
                            except: pass
                            break
                        if km == "JUMPI": break
                    break
                if jm in ("JUMPI", "JUMP"): break
    return dispatch, fallback


# ─────────────────────────────────────────────────────────────────────────────
#  ERROR STRING EXTRACTION  (from contiguous string blocks in bytecode)
# ─────────────────────────────────────────────────────────────────────────────
def extract_error_strings(bytecode_bytes):
    """
    Extract require() error strings from EVM bytecode.
    
    Solidity stores error strings in two patterns:
    1. Contiguous UTF-8 data block (0.6.x) — multiple PUSH32 back-to-back
    2. Individual PUSH32 with full string (0.8.x)
    
    We scan both patterns and return deduplicated list of (pc, msg).
    """
    errors = []
    seen = set()
    bc = bytecode_bytes
    
    # Pattern 1: Scan individual PUSH opcodes for printable runs
    i = 0
    while i < len(bc):
        op = bc[i]
        if 0x60 <= op <= 0x7f:
            sz = op - 0x5f
            if sz >= 15 and i + 1 + sz <= len(bc):
                data = bc[i+1:i+1+sz]
                try:
                    s = data.decode("utf-8", errors="replace")
                    for pattern in [
                        r"(SafeMath: [A-Za-z ]+ overflow)",
                        r"(SafeMath: [A-Za-z ]+ underflow)",
                        r"(ERC20: [A-Za-z ]{5,80})",
                        r"(ERC721: [A-Za-z ]{5,80})",
                        r"(ERC1155: [A-Za-z ]{5,80})",
                        r"(Ownable: [A-Za-z ]{5,80})",
                        r"(Pausable: [A-Za-z ]{5,40})",
                        r"(ReentrancyGuard: [A-Za-z ]{5,40})",
                        r"(DOGO_Dividend_Tracker: [A-Za-z0-9 ,.()'_]{5,200})",
                        r"(Address: [A-Za-z ]{5,60})",
                        r"(SafeERC20: [A-Za-z ]{5,40})",
                        r"(No transfers allowed[A-Za-z ]{0,40})",
                        r"(withdrawDividend disabled[A-Za-z .']{5,200})",
                        r"(claimWait must be updated[A-Za-z0-9 ]{5,100})",
                        r"(Cannot update claimWait[A-Za-z ]{5,60})",
                        r"(decreased allowance below zero[A-Za-z ]{0,40})",
                    ]:
                        for m in re.finditer(pattern, s):
                            msg = m.group(1).strip()
                            if msg not in seen and len(msg) > 10:
                                seen.add(msg)
                                errors.append((i, msg))
                except: pass
            i += 1 + sz
        else:
            i += 1
    
    # Pattern 2: Scan contiguous data blocks for full error messages
    # Find regions with high density of printable ASCII
    printable_runs = []
    run_start = None
    run_data = bytearray()
    
    for i in range(len(bc)):
        b = bc[i]
        if 32 <= b < 127 or b in (0x0a, 0x0d, 0x09):
            if run_start is None:
                run_start = i
            run_data.append(b)
        else:
            if run_data and len(run_data) >= 20:
                try:
                    text = run_data.decode("utf-8", errors="replace")
                    # Extract full error messages from the run
                    for pattern in [
                        r"(SafeMath: [A-Za-z ]+ overflow)",
                        r"(SafeMath: [A-Za-z ]+ underflow)",
                        r"(ERC20: [A-Za-z ]{5,80})",
                        r"(ERC721: [A-Za-z ]{5,80})",
                        r"(ERC1155: [A-Za-z ]{5,80})",
                        r"(Ownable: [A-Za-z ]{5,80})",
                        r"(Pausable: [A-Za-z ]{5,40})",
                        r"(ReentrancyGuard: [A-Za-z ]{5,40})",
                        r"(DOGO_Dividend_Tracker: [A-Za-z0-9 ,.()'_]{5,200})",
                        r"(Address: [A-Za-z ]{5,60})",
                        r"(SafeERC20: [A-Za-z ]{5,40})",
                    ]:
                        for m in re.finditer(pattern, text):
                            msg = m.group(1).strip()
                            if msg not in seen and len(msg) > 10:
                                seen.add(msg)
                                errors.append((run_start, msg))
                except: pass
            run_start = None
            run_data = bytearray()
    
    # Pattern 3: Direct byte search for known error fragments
    known_fragments = [
        b"No transfers allowed",
        b"withdrawDividend disabled",
        b"claimWait must be updated",
        b"Cannot update claimWait",
        b"SafeMath: subtraction overflow",
        b"SafeMath: addition overflow",
        b"SafeMath: multiplication overflow",
        b"ERC20: burn from the zero address",
        b"ERC20: burn amount exceeds balance",
        b"ERC20: mint to the zero address",
        b"ERC20: approve from the zero address",
        b"ERC20: approve to the zero address",
        b"ERC20: transfer amount exceeds",
        b"ERC20: decreased allowance below",
        b"Ownable: caller is not the owner",
        b"Ownable: new owner is the zero address",
    ]
    for fragment in known_fragments:
        idx = bc.find(fragment)
        if idx >= 0:
            # Expand to find full message boundaries
            start = idx
            end = idx + len(fragment)
            # Expand forward until non-printable or another known fragment start
            while end < len(bc) and end - idx < 200:
                b = bc[end]
                if 32 <= b < 127:
                    end += 1
                else:
                    break
            try:
                full_msg = bc[start:end].decode("utf-8", errors="replace").strip()
                # Trim at known boundary markers
                for marker in ["DOGO_", "ERC20:", "SafeMath:", "Ownable:", "Pausable:"]:
                    pos = full_msg.find(marker, 20)  # skip first 20 chars
                    if pos > 0:
                        full_msg = full_msg[:pos].strip()
                if full_msg not in seen and len(full_msg) > 10:
                    seen.add(full_msg)
                    errors.append((start, full_msg))
            except: pass
    
    return errors


def build_revert_error_map(bytecode_bytes, instrs, error_strings):
    """
    Build a map of REVERT instruction PC → error message string.
    
    Strategy: For each REVERT, scan backward in the bytecode for the
    nearest PUSH that contains or precedes an error string.
    """
    revert_map = {}
    if not bytecode_bytes or not error_strings:
        return revert_map
    
    bc = bytecode_bytes
    revert_pcs = [pc for pc, op, mnem, *_ in instrs if mnem == "REVERT"]
    
    for r_pc in revert_pcs:
        best_msg = None
        best_dist = 999
        
        # Scan backward from REVERT
        for lookback in range(1, min(r_pc, 500)):
            pos = r_pc - lookback
            if pos < 0 or pos >= len(bc):
                continue
            
            # Check if this position is near any error string
            for err_pc, msg in error_strings:
                # Error string starts at err_pc, REVERT at r_pc
                # They should be within reasonable distance
                dist = abs(pos - err_pc)
                if dist < 50 and len(msg) < best_dist:
                    best_dist = len(msg)
                    best_msg = msg
        
        if best_msg:
            revert_map[r_pc] = best_msg
    
    return revert_map


# ─────────────────────────────────────────────────────────────────────────────
#  PRIVATE FUNCTION DETECTION
# ─────────────────────────────────────────────────────────────────────────────
def detect_private_functions(cfg, dispatch, abi_results):
    """
    Find internal/private functions by identifying JUMPDEST blocks
    that are called (via JUMP) from public function bodies but are
    NOT public function entry points themselves.
    
    Returns list of (offset, caller_context) for each private function.
    """
    public_offsets = set()
    for r in abi_results:
        off = r.get("bytecode_offset")
        if off is not None:
            public_offsets.add(off)
    for off in dispatch.values():
        public_offsets.add(off)
    
    # Find all JUMPDEST targets
    all_jumpdests = set()
    for bs, blk in cfg.items():
        for pc, op, mnem, operand, gas, cat in blk["instrs"]:
            if mnem == "JUMPDEST":
                all_jumpdests.add(pc)
    
    # Find JUMP targets from within function bodies
    jump_targets = set()
    for bs, blk in cfg.items():
        for i, (pc, op, mnem, operand, gas, cat) in enumerate(blk["instrs"]):
            if mnem == "JUMP":
                # Look backward for PUSH with target
                for j in range(i-1, max(i-5, -1), -1):
                    jop = blk["instrs"][j][1]
                    joperand = blk["instrs"][j][3]
                    if 0x60 <= jop <= 0x7f and joperand:
                        try:
                            target = int(joperand.hex(), 16)
                            if target in all_jumpdests:
                                jump_targets.add(target)
                        except: pass
                        break
    
    # Private functions = jump targets that are NOT public entries
    private_fns = []
    for target in sorted(jump_targets):
        if target not in public_offsets and target in all_jumpdests:
            private_fns.append(target)
    
    return private_fns


def analyze_private_function(entry_off, cfg, storage_names, bytecode_bytes):
    """
    Analyze a private function: count operations, detect SafeMath patterns,
    infer name and behavior.
    """
    entry_block = None
    for bs, blk in cfg.items():
        for pc, *_ in blk["instrs"]:
            if pc == entry_off: entry_block = bs; break
        if entry_block is not None: break
    if entry_block is None: return None
    
    visited = []; queue = [entry_block]; seen = set()
    while queue and len(visited) < 30:
        cur = queue.pop(0)
        if cur in seen or cur not in cfg: continue
        seen.add(cur); visited.append(cur)
        for s in cfg[cur].get("successors", []):
            if s not in seen: queue.append(s)
    
    ops = {}
    for bs in visited:
        if bs not in cfg: continue
        for _, _, mnem, *_ in cfg[bs]["instrs"]:
            ops[mnem] = ops.get(mnem, 0) + 1
    
    # Detect SafeMath patterns
    has_sub = ops.get("SUB", 0) > 0
    has_mul = ops.get("MUL", 0) > 0
    has_add = ops.get("ADD", 0) > 0
    has_div = ops.get("DIV", 0) > 0
    has_revert = ops.get("REVERT", 0) > 0
    has_sload = ops.get("SLOAD", 0) > 0
    has_sstore = ops.get("SSTORE", 0) > 0
    has_caller = ops.get("CALLER", 0) > 0
    has_delegatecall = ops.get("DELEGATECALL", 0) > 0
    has_return = ops.get("RETURN", 0) > 0
    has_sha3 = ops.get("SHA3", 0) > 0  # keccak256 = mapping access
    has_log = any(ops.get(f"LOG{i}", 0) > 0 for i in range(5))
    has_callvalue = ops.get("CALLVALUE", 0) > 0
    has_calldataload = ops.get("CALLDATALOAD", 0) > 0
    has_arith = has_sub or has_add or has_mul or has_div
    total_ops = sum(ops.values())
    
    # SafeMath detection: small pure functions with arithmetic + revert
    if has_revert and has_arith and not has_sload and not has_sstore and total_ops < 60:
        if has_sub and not has_add and not has_mul:
            return {"offset": entry_off, "name": "_SafeSub", "type": "safemath"}
        if has_mul and has_div:
            return {"offset": entry_off, "name": "_SafeMul", "type": "safemath"}
        if has_add and not has_sub and not has_mul:
            return {"offset": entry_off, "name": "_SafeAdd", "type": "safemath"}
        # Generic SafeMath (mixed arithmetic)
        if has_sub:
            return {"offset": entry_off, "name": "_SafeSub", "type": "safemath"}
        if has_add:
            return {"offset": entry_off, "name": "_SafeAdd", "type": "safemath"}
        if has_mul:
            return {"offset": entry_off, "name": "_SafeMul", "type": "safemath"}
    
    if has_delegatecall and has_sload:
        return {"offset": entry_off, "name": f"_delegateCall_{entry_off:04x}", "type": "delegate"}
    if has_delegatecall:
        return {"offset": entry_off, "name": f"_delegateCall_{entry_off:04x}", "type": "delegate"}
    if has_sstore and has_caller:
        return {"offset": entry_off, "name": f"_adminFunc_{entry_off:04x}", "type": "admin"}
    if has_sstore and has_sha3:
        return {"offset": entry_off, "name": f"_mappingWrite_{entry_off:04x}", "type": "mapping_write"}
    if has_sstore and has_log:
        return {"offset": entry_off, "name": f"_stateChange_{entry_off:04x}", "type": "state_change"}
    if has_sload and has_sha3 and not has_sstore:
        return {"offset": entry_off, "name": f"_mappingRead_{entry_off:04x}", "type": "mapping_read"}
    if has_sload and not has_sstore:
        return {"offset": entry_off, "name": f"_storageRead_{entry_off:04x}", "type": "getter"}
    if has_calldataload and has_return and total_ops < 20:
        return {"offset": entry_off, "name": f"_argDecode_{entry_off:04x}", "type": "arg_decode"}
    if has_callvalue and has_revert:
        return {"offset": entry_off, "name": f"_payableGuard_{entry_off:04x}", "type": "payable_guard"}
    
    return {"offset": entry_off, "name": f"_internal_{entry_off:04x}", "type": "unknown"}


# ─────────────────────────────────────────────────────────────────────────────
#  SIGNATURE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def slot_name(slot_e, storage_names):
    """Resolve a slot expression to its human name."""
    for key in (slot_e, slot_e.lower()):
        if key in storage_names:
            return storage_names[key][0]
    try:
        si = int(slot_e, 0)
        for key in (str(si), hex(si), hex(si).lower()):
            if key in storage_names:
                return storage_names[key][0]
    except: pass
    return f"_storage[{slot_e}]"


def slot_type(slot_e, storage_names):
    """Get the declared type for a storage slot."""
    for key in (slot_e, slot_e.lower()):
        if key in storage_names:
            return storage_names[key][1]
    return "uint256"


def sig_to_sol(sig):
    if not sig: return None, [], []
    name = sig[:sig.index("(")] if "(" in sig else sig
    inner = sig[sig.index("(")+1:sig.rindex(")")] if "(" in sig else ""
    param_types = [t.strip() for t in inner.split(",") if t.strip()]
    param_names = [f"arg{i}" for i in range(len(param_types))]
    return name, param_types, param_names


def infer_return_type(sig, mut):
    if not sig: return ""
    low = sig.lower()
    name_part = low[:low.index("(")] if "(" in low else low
    
    uint_fns = ("balanceof","allowance","totalsupply","getreserves","price",
                "amount","fee","decimals","time","lock","timestamp","supply",
                "cap","rate","count","index","balance","minimum","withdrawable",
                "accumulative","dividend","last","claim","wait","processed",
                "tokenholders","holders","distributed","round","nonce","epoch")
    addr_fns = ("owner","token0","token1","impl","implementation","sender",
                "recipient","account","admin","router","factory","beacon","token")
    str_fns = ("name","symbol","uri","tokenuri")
    bool_fns = ("isapproved","paused","hasrole","supports","enabled","exists",
                "verified","active","whitelisted","excluded")
    
    if any(k in name_part for k in uint_fns): return "uint256"
    if any(k in name_part for k in addr_fns): return "address"
    if any(k in name_part for k in str_fns): return "string memory"
    if any(k in name_part for k in bool_fns): return "bool"
    return ""


def visibility(func_name):
    public_fns = {"name","symbol","decimals","totalSupply","balanceOf","owner",
                  "paused","getReserves","factory","token0","token1","fee",
                  "slot0","nonce","DOMAIN_SEPARATOR"}
    return "public" if func_name in public_fns else "external"


def state_mut_str(mut):
    m = (mut or "").lower()
    if m == "view": return "view"
    if m == "pure": return "pure"
    if m == "payable": return "payable"
    return ""


# ─────────────────────────────────────────────────────────────────────────────
#  DISPATCHER PREAMBLE SKIPPER
# ─────────────────────────────────────────────────────────────────────────────
def skip_dispatcher_preamble(instrs):
    if not instrs: return instrs
    start = 0
    if instrs[0][2] == "JUMPDEST": start = 1
    
    revert_seen = False
    for i in range(start, len(instrs)):
        pc, op, mnem, operand, gas, cat = instrs[i]
        if mnem == "REVERT": revert_seen = True; continue
        if revert_seen and mnem == "JUMPDEST":
            return instrs[i:]
    
    for i in range(start, min(start + 3, len(instrs))):
        mnem = instrs[i][2]
        if mnem in ("CALLDATALOAD", "CALLER", "CALLVALUE", "SLOAD"):
            return instrs[i:]
    return instrs[start:]


# ─────────────────────────────────────────────────────────────────────────────
#  STUB GENERATION
# ─────────────────────────────────────────────────────────────────────────────
from .stubs import KNOWN_STUBS


def generate_stub(func_name, param_names, param_types, ret_type, mut,
                  storage_names, evmole_stor, ops=None, error_strings=None):
    ops = ops or {}
    
    if func_name in KNOWN_STUBS:
        return KNOWN_STUBS[func_name](param_names)
    
    body = []
    has_storage_read = ops.get("SLOAD", 0) > 0
    has_storage_write = ops.get("SSTORE", 0) > 0
    has_caller = ops.get("CALLER", 0) > 0
    has_logs = ops.get("LOG0", 0) > 0
    has_delegatecall = ops.get("DELEGATECALL", 0) > 0
    has_revert = ops.get("REVERT", 0) > 0
    
    if ret_type == "bool":
        if has_storage_write:
            body.append("        // state-modifying function")
            body.append("        return true;")
        elif has_caller:
            body.append("        // checks msg.sender")
            body.append("        return true;")
        else:
            body.append("        return true;")
    elif ret_type == "uint256":
        if param_names and param_types and "address" in param_types[0]:
            if has_storage_read:
                mappings = []
                for rec in evmole_stor:
                    if "mapping" in str(rec.get("type", "")):
                        try: idx = int(rec["slot_hex"], 16)
                        except: idx = 999
                        name = storage_names.get(rec["slot_hex"], (rec["slot_hex"],))[0]
                        mappings.append((idx, name, rec))
                
                fn_lower = func_name.lower() if func_name else ""
                picked = None
                for idx, name, rec in mappings:
                    if name.lower() == f"_{fn_lower}":
                        picked = name; break
                if not picked:
                    for idx, name, rec in sorted(mappings, key=lambda x: x[0]):
                        if name not in ("_balanceOf", "_allowance", "_owner"):
                            picked = name; break
                if not picked and mappings: picked = mappings[0][1]
                
                if picked:
                    body.append(f"        return {picked}[{param_names[0]}];")
                else:
                    body.append("        return 0;")
            else:
                body.append("        return 0;")
        else:
            body.append("        return 0;")
    elif ret_type == "address":
        if has_storage_read: body.append("        // reads from storage")
        body.append("        return address(0);")
    elif ret_type == "string memory":
        body.append('        return "";')
    elif mut == "payable":
        body.append("        // payable — accepts ETH")
    elif has_delegatecall:
        body.append("        // delegates to external contract")
        body.append("        revert();")
    elif has_storage_write and has_caller:
        body.append("        // requires msg.sender auth, writes storage")
    elif has_storage_write:
        body.append("        // writes to storage")
    elif has_storage_read:
        body.append("        // reads from storage")
    elif has_revert and not has_storage_read:
        body.append("        revert();")
    elif param_names and param_types and "address" in param_types[0]:
        body.append("        // state-modifying function")
    else:
        body.append("        // body not traced")
    
    return body

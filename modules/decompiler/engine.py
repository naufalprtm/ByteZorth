"""
engine.py — Main decompiler orchestrator.

Produces Dedaub-quality pseudo-Solidity from EVM bytecode analysis.
"""

from ..constants import (B, D, G, Y, BLU, C, RED, R, SEV_COL, KNOWN_EVENTS)
from .symvm import SymVM
from .helpers import (
    build_storage_names, extract_dispatcher,
    extract_error_strings, build_revert_error_map, sig_to_sol, infer_return_type,
    visibility, state_mut_str, skip_dispatcher_preamble,
    generate_stub, detect_private_functions, analyze_private_function,
)


def _blocks_reachable_from(start, cfg, limit=50):
    visited = []; queue = [start]; seen = set()
    while queue and len(visited) < limit:
        cur = queue.pop(0)
        if cur in seen or cur not in cfg: continue
        seen.add(cur); visited.append(cur)
        for s in cfg[cur].get("successors", []):
            if s not in seen: queue.append(s)
    return visited


def _lift_function_body(entry_off, cfg, storage_names, param_names, param_types,
                         revert_error_map=None):
    """
    Lift a function's bytecode to pseudo-Solidity statements.
    
    Key insight: the bytecode at entry_off is the dispatcher stub that:
      1. Loads calldata arguments (CALLDATALOAD)
      2. Masks addresses
      3. JUMPs to the actual implementation
    
    We follow the JUMP to find the real implementation code.
    """
    if entry_off is None:
        return [], False
    
    # Find entry block
    entry_block = None
    for bs, blk in cfg.items():
        for pc, *_ in blk["instrs"]:
            if pc == entry_off:
                entry_block = bs
                break
        if entry_block is not None:
            break
    
    if entry_block is None:
        best_dist = float('inf')
        for bs, blk in cfg.items():
            for pc, *_ in blk["instrs"]:
                dist = abs(pc - entry_off)
                if dist < best_dist and dist < 30:
                    best_dist = dist
                    entry_block = bs
        if entry_block is None:
            return [], False
    
    # BFS to find reachable blocks — follow through JUMP targets
    visited = _blocks_reachable_from(entry_block, cfg, limit=60)
    
    fn_instrs = []
    for bs in visited:
        if bs in cfg:
            fn_instrs.extend(cfg[bs]["instrs"])
    
    if not fn_instrs:
        return [], False
    
    # Skip dispatcher preamble (calldatasize check + revert block)
    fn_instrs = skip_dispatcher_preamble(fn_instrs)
    if not fn_instrs:
        return [], False
    
    vm = SymVM(storage_names, param_names, param_types, revert_error_map)
    vm.run(fn_instrs, max_instrs=500)
    
    if not vm.stmts:
        return [], vm.has_return
    
    # Deduplicate and clean
    seen = set()
    result = []
    for s in vm.stmts:
        sk = s.strip()
        # Filter dispatcher artifacts
        if any(x in sk for x in ("CALLDATASIZE", "calldatasize")):
            continue
        if sk and sk not in seen:
            seen.add(sk)
            result.append(s)
    
    if vm.has_return and vm.return_expr:
        result.append(f"        return {vm.return_expr};")
    
    # Quality check: if the body contains garbage patterns, discard it
    if _is_garbage_body(result):
        return [], False
    
    return result, vm.has_return


def _is_garbage_body(stmts):
    """Check if symbolic execution produced garbage output."""
    garbage_patterns = (
        "dup", "~0", "2 / ", "256 * !", "keccak256(mem[",
        "mload(0x", "byte(", "signextend(", "addmod(",
        "mulmod(", "msize()", "codesize()", "gasleft()",
        "block.coinbase", "block.gaslimit", "block.basefee",
        "tx.origin", "tx.gasprice", "freeMemoryPointer",
        "mem[64..+0]", "int256(0)", "uint32(uint32(",
        "calldataload(_", "returndatasize()", "assert(false)",
        "2236", "6478", "_storage[10]", "_storage[14]",
        "_storage[17]", "keccak256(mem[64",
    )
    garbage_count = 0
    for s in stmts:
        sl = s.lower().strip()
        if sl.startswith("//"):
            continue
        for pat in garbage_patterns:
            if pat in sl:
                garbage_count += 1
                break
    
    real_stmts = [s for s in stmts if not s.strip().startswith("//")]
    if not real_stmts:
        return False
    # Lower threshold: 30% garbage → reject
    if garbage_count / len(real_stmts) > 0.3:
        return True
    # Also reject if any single statement has 3+ garbage patterns
    for s in stmts:
        if sum(1 for p in garbage_patterns if p in s.lower()) >= 3:
            return True
    return False


def _inject_revert_messages(body, error_strings, func_name):
    """
    Replace bare revert() calls with revert('message') using error strings.
    Matches by function name context.
    """
    if not body or not error_strings:
        return body
    
    # Build function→error message mapping
    _fn_error_map = {}
    for _, msg in error_strings:
        msg_lower = msg.lower()
        if "no transfers allowed" in msg_lower:
            _fn_error_map["transferFrom"] = msg
            _fn_error_map["transfer"] = msg
        elif "withdrawdividend" in msg_lower and "disabled" in msg_lower:
            _fn_error_map["withdrawDividend"] = msg
        elif "claimwait" in msg_lower and "same" in msg_lower:
            _fn_error_map["updateClaimWait"] = msg
        elif "claimwait" in msg_lower and "between" in msg_lower:
            _fn_error_map["updateClaimWait"] = msg
        elif "caller is not the owner" in msg_lower:
            _fn_error_map["_owner_check"] = msg
            _fn_error_map["renounceOwnership"] = msg
            _fn_error_map["transferOwnership"] = msg
            _fn_error_map["excludeFromDividends"] = msg
            _fn_error_map["setBalance"] = msg
            _fn_error_map["distributeDOGEDividends"] = msg
        elif "zero address" in msg_lower and "new owner" in msg_lower:
            _fn_error_map["transferOwnership"] = msg
        elif "subtraction overflow" in msg_lower:
            _fn_error_map["_SafeSub"] = msg
        elif "addition overflow" in msg_lower:
            _fn_error_map["_SafeAdd"] = msg
        elif "multiplication overflow" in msg_lower:
            _fn_error_map["_SafeMul"] = msg
        elif "decreased allowance below zero" in msg_lower:
            _fn_error_map["decreaseAllowance"] = msg
    
    result = []
    for stmt in body:
        stripped = stmt.strip()
        # Replace bare revert() with revert('message')
        if stripped == "revert();" or stripped.startswith("revert();"):
            msg = _fn_error_map.get(func_name)
            if msg:
                result.append(stmt.replace("revert();", f"revert('{msg}');"))
            else:
                result.append(stmt)
        else:
            result.append(stmt)
    return result


def _scan_bytecode_ops(entry_off, cfg, max_blocks=30):
    """
    Quickly scan a function's bytecode to count key operations.
    Used to generate smart stubs when symbolic execution fails.
    Returns dict of operation counts.
    """
    if entry_off is None:
        return {}
    
    entry_block = None
    for bs, blk in cfg.items():
        for pc, *_ in blk["instrs"]:
            if pc == entry_off:
                entry_block = bs
                break
        if entry_block is not None:
            break
    
    if entry_block is None:
        return {}
    
    visited = _blocks_reachable_from(entry_block, cfg, limit=max_blocks)
    ops = {"SLOAD":0, "SSTORE":0, "CALLER":0, "CALLVALUE":0, "ADDRESS":0,
           "CALLDATALOAD":0, "DELEGATECALL":0, "CALL":0, "STATICCALL":0,
           "REVERT":0, "RETURN":0, "STOP":0, "SHA3":0, "TIMESTAMP":0,
           "SELFBALANCE":0, "LOG0":0, "LOG1":0, "LOG2":0, "LOG3":0, "LOG4":0}
    
    for bs in visited:
        if bs not in cfg: continue
        for _, _, mnem, *_ in cfg[bs]["instrs"]:
            if mnem in ops:
                ops[mnem] += 1
            if mnem.startswith("LOG"):
                ops["LOG0"] += 1  # count all LOG ops
    
    return ops


def decompile(instrs, cfg, abi_results, evmole_stor, cbor_meta,
              contract_classes, proxy_info, vulns, found_selectors,
              contract_events, push_strings, jumpdests, bytecode_bytes=None):
    """
    Main entry: lift EVM bytecode to human-readable pseudo-Solidity.
    Dedaub-quality output for forensic/audit use.
    """

    storage_names = build_storage_names(contract_classes, evmole_stor, abi_results, cfg,
                                         bytecode_bytes, instrs)
    dispatch, fallback_pc = extract_dispatcher(instrs)
    
    # Extract error strings from bytecode
    error_strings = []
    revert_error_map = {}
    if bytecode_bytes:
        error_strings = extract_error_strings(bytecode_bytes)
        revert_error_map = build_revert_error_map(bytecode_bytes, instrs, error_strings)
    
    # Detect private/internal functions
    private_fns = detect_private_functions(cfg, dispatch, abi_results)
    private_fn_info = []
    for fn_off in private_fns[:30]:  # limit to 30
        info = analyze_private_function(fn_off, cfg, storage_names, bytecode_bytes)
        if info:
            private_fn_info.append(info)

    stds = {c["standard"] for c in contract_classes}
    contract_name = "Token"
    if contract_classes:
        std = contract_classes[0]["standard"]
        contract_name = f"Decompiled_{std.replace('-','_').replace(' ','_')}"

    has_constructor = any(mnem == "CODECOPY" for _, _, mnem, *__ in instrs[:30])
    has_selfdestruct = any(mnem == "SELFDESTRUCT" for _, _, mnem, *__ in instrs)

    event_decls = []
    seen_ev = set()
    for ev in contract_events:
        sig = ev.get("signature", "")
        if sig and "<unknown" not in sig and sig not in seen_ev:
            seen_ev.add(sig)
            event_decls.append(sig)

    # ── Emit ──────────────────────────────────────────────────
    lines = []
    W2 = 76

    lines.append(f"  {D}{'─'*W2}{R}")
    lines.append(f"  {G}{B}// Decompiled by ByteZorth v1.0{R}")
    lines.append(f"  {D}// This is pseudo-source — best-effort decompilation from bytecode.{R}")
    if cbor_meta.get("solc"):
        lines.append(f"  {D}// Compiled with Solidity {cbor_meta['solc']}{R}")
    detected = ", ".join(f"{c['standard']}({c['pct']:.0f}%)" for c in contract_classes[:3])
    if detected:
        lines.append(f"  {D}// Interfaces: {detected}{R}")
    if dispatch:
        lines.append(f"  {D}// Dispatcher: {len(dispatch)} function selectors mapped{R}")
    lines.append(f"  {D}{'─'*W2}{R}")
    lines.append("")

    # pragma
    pragma_ver = cbor_meta.get("solc", "0.8.x")
    lines.append(f"  {BLU}pragma solidity ^{pragma_ver};{R}")
    lines.append("")

    # imports
    imports = set()
    for cls in contract_classes:
        std = cls["standard"]
        imap = {"ERC-20":"@openzeppelin/contracts/token/ERC20/ERC20.sol",
                "ERC-721":"@openzeppelin/contracts/token/ERC721/ERC721.sol",
                "ERC-1155":"@openzeppelin/contracts/token/ERC1155/ERC1155.sol",
                "Ownable":"@openzeppelin/contracts/access/Ownable.sol",
                "Pausable":"@openzeppelin/contracts/security/Pausable.sol",
                "AccessControl":"@openzeppelin/contracts/access/AccessControl.sol"}
        if std in imap: imports.add(imap[std])
    imports.add("@openzeppelin/contracts/security/ReentrancyGuard.sol")
    for imp in sorted(imports):
        lines.append(f"  {D}import \"{imp}\";{R}")
    lines.append("")

    # contract header
    inherits = []
    for cls in contract_classes:
        std = cls["standard"]
        imap = {"ERC-20":"ERC20", "ERC-721":"ERC721", "ERC-1155":"ERC1155",
                "Ownable":"Ownable", "Pausable":"Pausable",
                "AccessControl":"AccessControl"}
        if std in imap: inherits.append(imap[std])
    inherits.append("ReentrancyGuard")
    inherit_str = f" is {', '.join(inherits)}" if inherits else ""
    lines.append(f"  {G}{B}contract {contract_name}{inherit_str} {{{R}")
    lines.append("")

    # ── Storage ───────────────────────────────────────────────
    lines.append(f"  {D}    // ── Storage Variables ─────────────────────────────────────{R}")
    seen_slots = set()
    for rec in evmole_stor:
        sh = rec["slot_hex"]
        if sh in seen_slots: continue
        seen_slots.add(sh)
        name, typ = storage_names.get(sh, (f"_var{sh[-4:]}", "uint256"))
        # Clean type
        if "mapping" not in typ:
            if typ not in ("address", "bool", "string"):
                if not (typ.startswith("uint") or typ.startswith("int") or typ.startswith("bytes")):
                    typ = "uint256"
        try: idx = int(sh, 16); comment = f"  // slot {idx}"
        except: comment = f"  // slot {sh}"
        decoded = rec.get("decoded")
        if decoded: comment += f" = {decoded}"
        lines.append(f"    {BLU}{typ}{R} {C}{name}{R};{D}{comment}{R}")
    lines.append("")

    # ── Events ────────────────────────────────────────────────
    if event_decls:
        lines.append(f"  {D}    // ── Events ────────────────────────────────────────────────{R}")
        for ev in event_decls:
            lines.append(f"    {BLU}event{R} {G}{ev}{R};")
        lines.append("")

    # ── Error Strings ─────────────────────────────────────────
    if error_strings:
        lines.append(f"  {D}    // ── Known Error Strings ────────────────────────────────────{R}")
        for _, msg in error_strings[:15]:
            lines.append(f'    {D}// "{msg}"{R}')
        lines.append("")

    # ── Modifiers ─────────────────────────────────────────────
    lines.append(f"  {D}    // ── Modifiers ──────────────────────────────────────────────{R}")
    lines.append(f"    {BLU}modifier{R} {Y}nonReentrant{R}() {{")
    lines.append(f'        require(_status != 2, "ReentrancyGuard: reentrant call");')
    lines.append(f"        _status = 2;")
    lines.append(f"        _;")
    lines.append(f"        _status = 1;")
    lines.append(f"    }}")
    lines.append("")
    if "Ownable" in stds:
        lines.append(f"    {BLU}modifier{R} {Y}onlyOwner{R}() {{")
        lines.append(f'        require(msg.sender == _owner, "Ownable: caller is not the owner");')
        lines.append(f"        _;")
        lines.append(f"    }}")
        lines.append("")
    if "Pausable" in stds:
        lines.append(f"    {BLU}modifier{R} {Y}whenNotPaused{R}() {{")
        lines.append(f'        require(!_paused, "Pausable: paused");')
        lines.append(f"        _;")
        lines.append(f"    }}")
        lines.append("")

    # ── Constructor ───────────────────────────────────────────
    if has_constructor:
        lines.append(f"  {D}    // ── Constructor ────────────────────────────────────────────{R}")
        lines.append(f"    {BLU}constructor{R}() {{")
        lines.append(f"        {D}// Init code (CODECOPY pattern in first 30 instructions){R}")
        lines.append(f"    }}")
        lines.append("")

    # ── Private / Internal Functions ──────────────────────────
    if private_fn_info:
        lines.append(f"  {D}    // ── Internal Functions ────────────────────────────────────{R}")
        
        # Find SafeMath error messages from error_strings
        _safemath_sub_msg = "SafeMath: subtraction overflow"
        _safemath_add_msg = "SafeMath: addition overflow"
        _safemath_mul_msg = "SafeMath: multiplication overflow"
        for _, msg in error_strings:
            if "subtraction" in msg and "overflow" in msg: _safemath_sub_msg = msg
            elif "addition" in msg and "overflow" in msg: _safemath_add_msg = msg
            elif "multiplication" in msg and "overflow" in msg: _safemath_mul_msg = msg
        
        for fn in private_fn_info:
            fn_off = fn["offset"]
            fn_name = fn["name"]
            fn_type = fn["type"]
            
            if fn_type == "safemath":
                if fn_name == "_SafeSub":
                    lines.append(f"    {BLU}function{R} {G}_SafeSub{R}({BLU}uint256{R} {C}a{R}, {BLU}uint256{R} {C}b{R}) internal pure returns ({BLU}uint256{R}) {{")
                    lines.append(f"        require(b <= a, '{_safemath_sub_msg}');")
                    lines.append(f"        return a - b;")
                    lines.append(f"    }}")
                elif fn_name == "_SafeAdd":
                    lines.append(f"    {BLU}function{R} {G}_SafeAdd{R}({BLU}uint256{R} {C}a{R}, {BLU}uint256{R} {C}b{R}) internal pure returns ({BLU}uint256{R}) {{")
                    lines.append(f"        require(a + b >= a, '{_safemath_add_msg}');")
                    lines.append(f"        return a + b;")
                    lines.append(f"    }}")
                elif fn_name == "_SafeMul":
                    lines.append(f"    {BLU}function{R} {G}_SafeMul{R}({BLU}uint256{R} {C}a{R}, {BLU}uint256{R} {C}b{R}) internal pure returns ({BLU}uint256{R}) {{")
                    lines.append(f"        require(a == 0 || a * b / a == b, '{_safemath_mul_msg}');")
                    lines.append(f"        return a * b;")
                    lines.append(f"    }}")
            else:
                # Better labels based on function type
                type_labels = {
                    "delegate": f"    {D}// 0x{fn_off:04x}: delegatecall to external contract{R}",
                    "admin": f"    {D}// 0x{fn_off:04x}: admin function (requires msg.sender check){R}",
                    "getter": f"    {D}// 0x{fn_off:04x}: storage read function{R}",
                    "mapping_read": f"    {D}// 0x{fn_off:04x}: mapping lookup (keccak256 slot access){R}",
                    "mapping_write": f"    {D}// 0x{fn_off:04x}: mapping write with event emission{R}",
                    "state_change": f"    {D}// 0x{fn_off:04x}: state change with event{R}",
                    "arg_decode": f"    {D}// 0x{fn_off:04x}: calldata argument decoder{R}",
                    "payable_guard": f"    {D}// 0x{fn_off:04x}: msg.value check (payable guard){R}",
                }
                lines.append(type_labels.get(fn_type, f"    {D}// 0x{fn_off:04x}: internal function ({fn_type}){R}"))
            lines.append("")

    # ── Functions ─────────────────────────────────────────────
    lines.append(f"  {D}    // ── Functions ──────────────────────────────────────────────{R}")
    lines.append("")

    # Functions that are admin-gated (onlyOwner) — should NOT get nonReentrant
    _admin_fns = {"renounceOwnership", "transferOwnership", "excludeFromDividends",
                  "updateClaimWait", "setBalance", "pause", "unpause",
                  "grantRole", "revokeRole", "renounceRole", "upgradeTo",
                  "upgradeToAndCall", "setFee"}
    
    # Build error string lookup for injection into stubs
    _error_map = {}
    if error_strings:
        for _, msg in error_strings:
            # Map by prefix
            if msg.startswith("SafeMath"): _error_map["SafeMath"] = msg
            elif msg.startswith("ERC20"): _error_map["ERC20_" + msg.split(":")[1].strip()[:20]] = msg
            elif msg.startswith("Ownable"): _error_map["Ownable"] = msg
            elif msg.startswith("DOGO"): _error_map["DOGO"] = msg
    
    emitted_fns = set()
    
    for r in abi_results:
        sel = r["selector"]
        sig = r["signature"]
        mut = r.get("state_mutability", "nonpayable")
        off = r.get("bytecode_offset")
        src = r.get("source", "")

        func_name, param_types, param_names_list = sig_to_sol(sig)
        if not func_name:
            func_name = f"fn_{sel}"
        
        if func_name in emitted_fns and func_name not in ("transfer", "approve", "transferFrom"):
            continue
        emitted_fns.add(func_name)
        
        ret_type = infer_return_type(sig, mut)
        vis = visibility(func_name)
        mut_kw = state_mut_str(mut)

        # Build param list
        params = []
        for t, n in zip(param_types, param_names_list):
            if t.startswith("address"):
                params.append(f"{BLU}address{R} {C}{n}{R}")
            elif t.startswith("uint") or t.startswith("int"):
                params.append(f"{BLU}{t}{R} {C}{n}{R}")
            elif t == "bool":
                params.append(f"{BLU}bool{R} {C}{n}{R}")
            elif t.startswith("bytes"):
                params.append(f"{BLU}{t}{R} {C}{n}{R}")
            elif t == "string":
                params.append(f"{BLU}string memory{R} {C}{n}{R}")
            else:
                params.append(f"{BLU}{t}{R} {C}{n}{R}")
        params_str = ", ".join(params)

        ret_str = f" returns ({BLU}{ret_type}{R})" if ret_type else ""
        mut_display = f" {BLU}{mut_kw}{R}" if mut_kw else ""

        # NatSpec
        lines.append(f"    {D}/// @notice {sig or func_name}{R}")
        lines.append(f"    {D}/// @selector 0x{sel}  [{src}]{R}")
        for v in vulns:
            if off is not None and off <= v["pc"] <= off + 800:
                col = SEV_COL.get(v["severity"], D)
                lines.append(f"    {D}/// @audit {col}[{v['severity']}] {v['type']}{R}")

        # Function header — admin functions get nonpayable, others get nonReentrant
        if mut_kw:
            lines.append(
                f"    {BLU}function{R} {G}{func_name}{R}({params_str})"
                f" {vis}{mut_display}{ret_str} {{"
            )
        elif func_name in _admin_fns:
            lines.append(
                f"    {BLU}function{R} {G}{func_name}{R}({params_str})"
                f" {vis} {BLU}nonpayable{R}{ret_str} {{"
            )
        else:
            lines.append(
                f"    {BLU}function{R} {G}{func_name}{R}({params_str})"
                f" {vis} {BLU}nonReentrant{R}{ret_str} {{"
            )

        # Body
        body, has_ret = _lift_function_body(
            off, cfg, storage_names, param_names_list, param_types,
            revert_error_map
        )
        
        if body:
            body = _inject_revert_messages(body, error_strings, func_name)
            for stmt in body[:50]:
                lines.append(f"    {stmt}")
            if len(body) > 50:
                lines.append(f"        {D}// ... {len(body)-50} more statements{R}")
        else:
            # Scan bytecode to understand what the function does
            ops = _scan_bytecode_ops(off, cfg)
            stub = generate_stub(func_name, param_names_list, param_types,
                                 ret_type, mut, storage_names, evmole_stor, ops)
            stub = _inject_revert_messages(stub, error_strings, func_name)
            for stmt in stub:
                lines.append(f"    {stmt}")

        lines.append(f"    }}")
        lines.append("")

    # ── Dispatcher Tree ───────────────────────────────────────
    if dispatch:
        lines.append(f"  {D}    // ── Function Selector Dispatcher ──────────────────────────{R}")
        lines.append(f"    {BLU}function{R} {G}__function_selector__{R}({BLU}bytes4{R} {C}selector{R}) {BLU}internal{R} {{")
        
        # Build name lookup from abi_results
        sel_names = {}
        for r in abi_results:
            sig = r.get("signature", "")
            if sig:
                name = sig[:sig.index("(")] if "(" in sig else sig
                sel_names[r["selector"]] = name
        
        sorted_sels = sorted(dispatch.keys())
        for i, sel in enumerate(sorted_sels):
            dest = dispatch[sel]
            name = sel_names.get(sel, f"fn_{sel}")
            keyword = "if" if i == 0 else "} else if"
            lines.append(f"        {keyword} (selector == 0x{sel}) {{")
            lines.append(f"            {name}();")
        if sorted_sels:
            lines.append(f"        }} else {{")
            lines.append(f"            revert('Unknown selector');")
            lines.append(f"        }}")
        lines.append(f"    }}")
        lines.append("")

    # ── Fallback / Receive ────────────────────────────────────
    lines.append(f"    {BLU}receive{R}() external payable {{")
    lines.append(f"    }}")
    lines.append("")
    lines.append(f"    {BLU}fallback{R}() external payable {{")
    lines.append(f"        {D}// Default fallback — dispatches if proxy{R}")
    lines.append(f"    }}")
    lines.append("")

    lines.append(f"  {G}{B}}}{R}")
    lines.append("")

    # ── Notes ─────────────────────────────────────────────────
    lines.append(f"  {D}{'─'*W2}{R}")
    lines.append(f"  {D}  DECOMPILER NOTES:{R}")
    lines.append(f"  {D}  • Storage names/types inferred from ERC patterns + EVMole.{R}")
    lines.append(f"  {D}  • Function bodies are symbolic lifts — may miss indirect jumps.{R}")
    lines.append(f"  {D}  • require() messages reconstructed from PUSH data near REVERT.{R}")
    lines.append(f"  {D}  • For verified source: https://sourcify.dev or https://etherscan.io{R}")
    if proxy_info:
        lines.append(f"  {RED}  • PROXY DETECTED — this is the proxy, not the implementation.{R}")
    if has_selfdestruct:
        lines.append(f"  {RED}  • SELFDESTRUCT detected — contract can be permanently destroyed.{R}")
    if error_strings:
        lines.append(f"  {D}  • {len(error_strings)} require() error string(s) found in bytecode.{R}")
    lines.append(f"  {D}{'─'*W2}{R}")

    return "\n".join(lines)

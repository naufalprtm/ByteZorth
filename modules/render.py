"""
render.py - Terminal and file output renderers

Terminal:  sections 0-4, 8-12 (forensic summary — fast, readable)
result.txt/json:  all sections (complete report)
result-lowlevel.txt/json:  [5] storage, [6] disassembly, [7] CFG, [9] vuln details
"""

import json, re, collections
from datetime import datetime
from pathlib import Path
from .constants import (B, D, G, Y, BLU, C, RED, R, CAT_COL, SEV_COL, MUT_COL,
                         SRC_COL, ERC_IFACE, CHAINS, fmt_mut, fmt_src, ruler, wordwrap)

_ANSI = re.compile(r'\033\[[0-9;]*m')
_strip = lambda s: _ANSI.sub('', s)


def render_terminal(instrs, cfg, jumpdests, loop_blocks, abi_results, contract_classes,
                    found_selectors, contract_events, evmole_stor, proxy_info,
                    vulns, push_strings, four_byte_hits, cbor_meta, byte_ent,
                    cat_counts, mnem_counts, total_gas, local_db, parquet_cache,
                    parquet_available, parquet_file_count, parquet_loaded,
                    sourcify_dir, no_net, contract_addr, active_chain, active_rpc,
                    contract_meta, bytecode, byte_len, code_end, byte_file,
                    pseudo_src, show_strings=False):
    """Render terminal output — forensic summary only (no raw disasm/CFG)."""

    ci = CHAINS.get(active_chain, {})
    resolved = [r for r in abi_results if r["signature"]]
    unresolved = [r for r in abi_results if not r["signature"]]
    W = 76

    import hashlib
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    md5_val    = hashlib.md5(bytecode).hexdigest()
    sha256_val = hashlib.sha256(bytecode).hexdigest()

    print()
    print(f"{B}{'='*W}{R}")
    print(f"{B}  ByteZorth  v1.0{R}")
    print(f"{B}{'='*W}{R}")

    # ── [0] METADATA ─────────────────────────────────────────────
    print(ruler("0  METADATA", W))
    print(f"  Generated      : {generated}")
    print(f"  File           : {byte_file}")
    print(f"  Total size     : {byte_len:,} bytes  ({byte_len*2:,} hex chars)")
    print(f"  Code size      : {code_end:,} bytes  (excl. CBOR metadata suffix)")
    print(f"  Byte entropy   : {byte_ent:.4f} bits / byte  "
          f"{'[high -- packed or obfuscated]' if byte_ent>7.5 else '[normal]' if byte_ent>5.5 else '[low -- sparse]'}")
    print(f"  MD5            : {md5_val}")
    print(f"  SHA256         : {sha256_val}")
    print(f"  Total opcodes  : {len(instrs)}")
    print(f"  Basic blocks   : {len(cfg)}  ({len(loop_blocks)} contain back-edges / loops)")
    print(f"  JUMPDESTs      : {len(jumpdests)}")
    print(f"  Local sel. DB  : {len(local_db):,} selectors")
    if parquet_available:
        print(f"  Parquet sig DB : {G}{len(parquet_cache):,} selectors{R}  "
              f"{D}({parquet_file_count} files from {sourcify_dir}/){R}")
    elif parquet_loaded and not parquet_available:
        if Path(sourcify_dir).is_dir() and parquet_file_count > 0:
            print(f"  Parquet sig DB : {RED}0 selectors loaded{R}  "
                  f"{D}({parquet_file_count} files found but no rows parsed){R}")
        else:
            print(f"  Parquet sig DB : {Y}not found{R}  "
                  f"{D}(looked in {sourcify_dir}/){R}")
    if no_net:
        print(f"  Network        : {Y}DISABLED (--no-net){R}")
    if contract_addr:
        print(f"  Contract       : {contract_addr}")
        print(f"  Chain          : {ci.get('name','?')}  (id={active_chain}, {ci.get('symbol','?')})")
        print(f"  RPC            : {active_rpc}")
        for k,v in contract_meta.items():
            print(f"  {k:<15}: {v}")

    # ── [1] COMPILER FINGERPRINT ─────────────────────────────────
    print(ruler("1  COMPILER FINGERPRINT  (CBOR metadata)", W))
    if cbor_meta.get("solc"):
        solc = cbor_meta["solc"]
        parts = solc.split("."); major,minor,patch = int(parts[0]),int(parts[1]),int(parts[2])
        overflow_safe = (major,minor) >= (0,8)
        print(f"  Compiler       : {G}Solidity {solc}{R}")
        print(f"  Overflow safe  : {(G+'yes (>=0.8, checks built-in)') if overflow_safe else (Y+'no  (<0.8 -- SafeMath required)')}{R}")
        print(f"  ABI Encoder v2 : {'yes' if (major,minor)>=(0,5) else 'no'}")
        print(f"  Experimental   : {cbor_meta.get('experimental', False)}")
    else:
        print(f"  {Y}Compiler version not found in CBOR block.{R}")
        if not cbor_meta.get("cbor_len"):
            print(f"  {D}No CBOR suffix detected -- may be Vyper, Yul, hand-assembled EVM.{R}")
    if cbor_meta.get("ipfs_cid"):
        print(f"  IPFS CID       : {BLU}{cbor_meta['ipfs_cid']}{R}")
        print(f"  Retrieve src   : {D}ipfs cat {cbor_meta['ipfs_cid']}{R}")
    for k in ("bzzr0","bzzr1"):
        if cbor_meta.get(k): print(f"  {k.upper()}           : {D}{cbor_meta[k]}{R}")
    if cbor_meta.get("cbor_len"):
        print(f"  CBOR offset    : 0x{cbor_meta['cbor_offset']:04x}  "
              f"(block length = {cbor_meta['cbor_len']} bytes)")

    # ── [2] CONTRACT CLASSIFICATION ──────────────────────────────
    print(ruler("2  CONTRACT CLASSIFICATION", W))
    if contract_classes:
        for cls in contract_classes:
            std = cls["standard"]; pct = cls["pct"]
            conf = G if pct==100 else Y if pct>=75 else RED
            filled = int(pct/10); bar = conf+"█"*filled+D+"░"*(10-filled)+R
            opt_note = f"  +{len(cls['optional'])} optional" if cls["optional"] else ""
            print(f"  {conf}{B}{std:<22}{R}  {bar}  {conf}{pct:.0f}%{R}  "
                  f"{D}({len(cls['matched'])}/{len(cls['required'])} required{opt_note}){R}")
            missing = [s for s in cls["required"] if s not in found_selectors]
            if missing:
                names = [ERC_IFACE[s][1] for s in missing[:4]]
                print(f"  {D}  missing: {', '.join(names)}{R}")
    else:
        print(f"  {D}No standard ERC interface pattern matched (>=50% threshold).{R}")

    # ── [3] FUNCTION ABI ─────────────────────────────────────────
    print(ruler("3  FUNCTION ABI", W))
    print(f"  {len(abi_results)} function(s)  --  {len(resolved)} resolved  /  {len(unresolved)} unknown\n")
    print(f"  {D}{'SELECTOR':<12}  {'SIGNATURE':<44}  {'MUT':<13}  {'@OFF':<7}  SOURCE{R}")
    print(f"  {D}{'─'*12}  {'─'*44}  {'─'*13}  {'─'*7}  {'─'*16}{R}")
    for r in abi_results:
        sel = f"{C}0x{r['selector']}{R}"
        if r["signature"]:
            nm = r["signature"].split("(")[0]; rest = r["signature"][len(nm):]
            sig = f"{B}{nm}{R}{D}{rest}{R}"
        else:
            sig = f"{Y}<unknown>{R}"
        mut = fmt_mut(r["state_mutability"])
        off = f"{D}{r['bytecode_offset']:<7}{R}" if r["bytecode_offset"] is not None else f"{D}?{R}"
        src = fmt_src(r["source"])
        erc_tag = f"  {D}[{ERC_IFACE[r['selector']][0]}]{R}" if r["selector"] in ERC_IFACE else ""
        print(f"  {sel:<12}  {sig:<44}  {mut:<13}  {off}  {src}{erc_tag}")
    if unresolved:
        print(f"\n  Selectors not found in any database:")
        for r in unresolved:
            a_note = f"  args:({r['arguments']})" if r["arguments"] else ""
            print(f"  {C}0x{r['selector']}{R}{D}{a_note}{R}  {fmt_mut(r['state_mutability'])}  {D}@{r['bytecode_offset']}{R}")

    # ── [4] EVENT SIGNATURES ─────────────────────────────────────
    print(ruler("4  EVENT SIGNATURES", W))
    if contract_events:
        print(f"  {len(contract_events)} event topic(s) found\n")
        print(f"  {D}{'TOPIC':<66}  EVENT{R}")
        print(f"  {D}{'─'*66}  {'─'*30}{R}")
        for e in contract_events:
            known = e["signature"]; col = G if "<unknown" not in known else Y
            print(f"  {D}0x{e['topic'][:16]}...{R}  {col}{known}{R}")
    else:
        print(f"  {D}No event topics detected.{R}")

    # ── [8] OPCODE STATISTICS ────────────────────────────────────
    print(ruler("8  OPCODE STATISTICS", W))
    print(f"  Total instructions : {len(instrs)}")
    print(f"  Static gas sum     : {total_gas:,}")
    print(f"  Byte entropy       : {byte_ent:.4f} bits/byte  (max 8.0)\n")
    print(f"  {D}{'CATEGORY':<14}  {'COUNT':>6}  {'%':>6}  BAR{R}")
    print(f"  {D}{'─'*14}  {'─'*6}  {'─'*6}  {'─'*26}{R}")
    for cat, cnt in cat_counts.most_common():
        pct = cnt/len(instrs)*100
        col = CAT_COL.get(cat,D)
        bar = col+"█"*int(pct/2)+R
        print(f"  {D}{cat:<14}{R}  {cnt:>6}  {pct:>5.1f}%  {bar}")
    print(f"\n  Top 12 opcodes:")
    for mnem, cnt in mnem_counts.most_common(12):
        print(f"  {D}  {mnem:<20} {cnt:>5}x{R}")

    # ── [9] VULNERABILITY SCAN (summary only) ────────────────────
    print(ruler("9  VULNERABILITY SCAN", W))
    if vulns:
        sev_sum = collections.Counter(v["severity"] for v in vulns)
        parts = []
        for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            if s in sev_sum:
                col = SEV_COL.get(s,"")
                parts.append(f"{col}{s}: {sev_sum[s]}{R}")
        print(f"  Summary: {' | '.join(parts)}\n")
        for v in vulns[:8]:
            col = SEV_COL.get(v["severity"],D)
            print(f"  {col}[{v['severity']:<8}]{R}  {B}{v['type']}{R}  {D}@ 0x{v['pc']:04x}{R}")
        if len(vulns) > 8:
            print(f"\n  {D}... {len(vulns)-8} more. Full details in result-lowlevel.txt{R}")
    else:
        print(f"  {G}No vulnerability patterns detected.{R}")

    # ── [10] STRINGS AND CONSTANTS ───────────────────────────────
    print(ruler("10 STRINGS AND CONSTANTS", W))
    if four_byte_hits:
        print(f"  Known 4-byte signatures found in push data:")
        for pc, h, name in four_byte_hits:
            print(f"  {D}0x{pc:04x}{R}  {C}0x{h}{R}  {G}{name}{R}")
        print()
    unique_strs = list(dict.fromkeys(text for _,_,text in push_strings))
    if unique_strs:
        print(f"  Push-data UTF-8 strings ({len(unique_strs)}):")
        for s in unique_strs[:20]:
            print(f"  {D}{repr(s)}{R}")
        if len(unique_strs) > 20:
            print(f"  {D}... {len(unique_strs)-20} more in result-lowlevel.txt{R}")
    else:
        print(f"  {D}No printable UTF-8 strings found.{R}")

    # ── PUSH Strings (detailed, --show-strings only) ────────────
    if show_strings and push_strings:
        print(ruler("10b PUSH STRINGS (detailed)", W))
        seen = set()
        for pc, mnem, text in push_strings:
            key = (mnem, text)
            if key in seen: continue
            seen.add(key)
            print(f"  {D}{mnem:<10}{R} @{pc:<6}  {G}\"{text}\"{R}")

    # ── [11] LIVE CHAIN SUMMARY ──────────────────────────────────
    if contract_addr:
        print(ruler("11 LIVE CHAIN SUMMARY", W))
        print(f"  Contract   : {contract_addr}")
        print(f"  Chain      : {ci.get('name','?')} (id={active_chain}, {ci.get('symbol','?')})")
        print(f"  RPC        : {active_rpc}")
        for k, v in contract_meta.items():
            print(f"  {k:<14}: {v}")
        if proxy_info:
            print(f"\n  Proxy implementation:")
            for label, addr in proxy_info.items():
                print(f"  {label:<32}: {C}{addr}{R}")

    # ── [12] PSEUDO-SOURCE ───────────────────────────────────────
    print(ruler("12 PSEUDO-SOURCE (DECOMPILED)", W))
    print(pseudo_src)

    print(f"\n{B}{'='*W}{R}\n")

    return generated, md5_val, sha256_val, unique_strs


# ─────────────────────────────────────────────────────────────────────────────
#  SAVE: result.txt / result.json  (full report — all sections)
# ─────────────────────────────────────────────────────────────────────────────
def save_txt(path, generated, byte_file, byte_len, contract_addr, ci, active_chain,
             active_rpc, md5_val, sha256_val, byte_ent, cbor_meta, contract_classes,
             abi_results, ERC_IFACE, contract_events, evmole_stor, vulns, instrs,
             cfg, loop_blocks, push_strings, four_byte_hits, pseudo_src):
    """Save full text report (all sections)."""
    W = 76
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"ByteZorth  v1.0\nGenerated: {generated}\n")
        f.write(f"File     : {byte_file}  ({byte_len:,} bytes)\n")
        f.write(f"Contract : {contract_addr or 'N/A'}  Chain: {ci.get('name','?')} (id={active_chain})\n")
        f.write(f"MD5      : {md5_val}\nSHA256   : {sha256_val}\n")
        f.write(f"Entropy  : {byte_ent:.4f} bits/byte\n")
        f.write("="*W+"\n\n")
        f.write("[0] COMPILER (CBOR)\n"+"-"*W+"\n")
        for k,v in cbor_meta.items(): f.write(f"  {k}: {v}\n")
        f.write("\n[1] CLASSIFICATION\n"+"-"*W+"\n")
        for cls in contract_classes:
            f.write(f"  {cls['standard']:<22} {cls['pct']:.0f}%  ({len(cls['matched'])}/{len(cls['required'])} required)\n")
        f.write("\n[2] FUNCTION ABI\n"+"-"*W+"\n")
        for r in abi_results:
            erc = f"  [{ERC_IFACE[r['selector']][0]}]" if r["selector"] in ERC_IFACE else ""
            f.write(f"0x{r['selector']}  {r['signature'] or '<unknown>':<50} [{r['state_mutability']:<11}]  @{r['bytecode_offset']}  [{r['source']}]{erc}\n")
        f.write("\n[3] EVENTS\n"+"-"*W+"\n")
        for e in contract_events:
            f.write(f"0x{e['topic']}  {e['signature']}\n")
        f.write("\n[4] STORAGE\n"+"-"*W+"\n")
        for s in evmole_stor:
            f.write(f"slot {s['slot_display']:<8}  off {s['offset']}  {s['type']:<18}  {s['decoded'] or '(empty)'}\n")
        f.write("\n[12] PSEUDO-SOURCE (DECOMPILED)\n"+"-"*W+"\n")
        f.write(_strip(pseudo_src)+"\n")


def save_json(path, generated, byte_file, byte_len, code_end, byte_ent,
              md5_val, sha256_val, contract_addr, active_chain, active_rpc,
              ci, contract_meta, cbor_meta, contract_classes, proxy_info,
              abi_results, contract_events, evmole_stor, vulns, instrs,
              cfg, loop_blocks, jumpdests, cat_counts, mnem_counts, total_gas,
              unique_strs, four_byte_hits, pseudo_src):
    """Save JSON report (all sections)."""
    with open(path, "w") as f:
        json.dump({
            "meta":{"generated":generated,"file":byte_file,"bytes":byte_len,
                    "code_bytes":code_end,"entropy":round(byte_ent,4),
                    "md5":md5_val,"sha256":sha256_val,
                    "contract":contract_addr,"chain_id":active_chain,
                    "chain_name":ci.get("name"),"rpc":active_rpc,**contract_meta},
            "compiler":cbor_meta,
            "classification":[{"standard":c["standard"],"confidence_pct":round(c["pct"],1),
                               "matched":c["matched"],"required":c["required"]}
                              for c in contract_classes],
            "proxy":proxy_info,
            "functions":abi_results,
            "events":contract_events,
            "storage":[{"slot":s["slot_display"],"slot_hex":s["slot_hex"],"offset":s["offset"],
                        "type":s["type"],"live_value":s["live_value"],"decoded":s["decoded"]}
                       for s in evmole_stor],
            "vulnerabilities":vulns,
            "statistics":{"total_instructions":len(instrs),"static_gas":total_gas,
                          "basic_blocks":len(cfg),"loop_blocks":len(loop_blocks),
                          "jump_destinations":len(jumpdests),
                          "entropy":round(byte_ent,4),
                          "categories":dict(cat_counts),
                          "top_opcodes":dict(mnem_counts.most_common(20))},
            "strings":unique_strs[:100],
            "four_byte_hits":[{"pc":pc,"selector":h,"name":name} for pc,h,name in four_byte_hits],
            "pseudo_source": _strip(pseudo_src),
        }, f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
#  SAVE: result-lowlevel.txt / result-lowlevel.json
#  [5] VULNERABILITIES  [6] FULL DISASSEMBLY  [7] CONTROL FLOW GRAPH
# ─────────────────────────────────────────────────────────────────────────────
def save_lowlevel_txt(path, vulns, instrs, cfg, jumpdests, loop_blocks, push_strings, four_byte_hits):
    """Save low-level forensic data: vulns, disassembly, CFG, strings."""
    W = 76
    with open(path, "w", encoding="utf-8") as f:
        f.write("ByteZorth  v1.0\n")
        f.write("LOW-LEVEL FORENSIC DATA\n")
        f.write("="*W+"\n\n")

        # [5] VULNERABILITIES
        f.write("[5] VULNERABILITIES (full details)\n"+"-"*W+"\n")
        if vulns:
            for v in vulns:
                f.write(f"[{v['severity']:<8}]  {v['type']:<28}  @ 0x{v['pc']:04x}\n")
                f.write(f"  {v['desc']}\n\n")
        else:
            f.write("  None detected.\n\n")

        # [6] FULL DISASSEMBLY
        f.write("[6] FULL DISASSEMBLY\n"+"-"*W+"\n")
        for pc,op,mnem,operand,gas,cat in instrs:
            oper = ("0x"+operand.hex()) if operand else ""
            f.write(f"0x{pc:05x}  0x{op:02x}  {mnem:<16}  {oper:<44}  gas={gas:<5}  [{cat}]\n")

        # [7] CONTROL FLOW GRAPH
        f.write("\n[7] CONTROL FLOW GRAPH\n"+"-"*W+"\n")
        f.write(f"  {len(cfg)} blocks | {len(jumpdests)} jumpdests | {len(loop_blocks)} loop blocks\n\n")
        for bstart in sorted(cfg.keys()):
            blk = cfg[bstart]
            loop = " [LOOP]" if bstart in loop_blocks else ""
            succs = ", ".join(f"0x{s:04x}" for s in blk["successors"])
            f.write(f"BLOCK 0x{bstart:04x}  ({len(blk['instrs']):>3} instrs)  "
                    f"end={blk['end_op']:<16}{loop}  -> [{succs}]\n")

        # [8] STRINGS (full)
        f.write("\n[8] STRINGS & CONSTANTS\n"+"-"*W+"\n")
        f.write("\n=== ALL PUSH WITH PRINTABLE STRINGS ===\n")
        seen = set()
        for pc, mnem, text in push_strings:
            key = (mnem, text)
            if key in seen: continue
            seen.add(key)
            f.write(f'  {mnem:<10} @{pc:<6}  "{text}"\n')
        for pc, h, name in four_byte_hits: f.write(f"  0x{pc:04x}  0x{h}  {name}\n")


def save_lowlevel_json(path, vulns, instrs, cfg, jumpdests, loop_blocks,
                       cat_counts, mnem_counts, total_gas, push_strings, four_byte_hits):
    """Save low-level forensic data as JSON."""
    unique_strs = list(dict.fromkeys(text for _,_,text in push_strings))
    with open(path, "w") as f:
        json.dump({
            "vulnerabilities": vulns,
            "disassembly": [
                {"pc":pc, "op":f"0x{op:02x}", "mnemonic":mnem,
                 "operand":"0x"+operand.hex() if operand else "",
                 "gas":gas, "category":cat}
                for pc,op,mnem,operand,gas,cat in instrs
            ],
            "cfg": {
                f"0x{bs:04x}": {
                    "instr_count": len(blk["instrs"]),
                    "end_op": blk["end_op"],
                    "is_loop": bs in loop_blocks,
                    "successors": [f"0x{s:04x}" for s in blk["successors"]],
                    "predecessors": [f"0x{p:04x}" for p in blk["predecessors"]],
                }
                for bs, blk in cfg.items()
            },
            "jumpdests": [f"0x{j:04x}" for j in sorted(jumpdests)],
            "loop_blocks": [f"0x{l:04x}" for l in sorted(loop_blocks)],
            "statistics": {
                "total_instructions": len(instrs),
                "static_gas": total_gas,
                "basic_blocks": len(cfg),
                "loop_blocks": len(loop_blocks),
                "categories": dict(cat_counts),
                "top_opcodes": dict(mnem_counts.most_common(30)),
            },
            "strings": unique_strs,
            "four_byte_hits": [{"pc":pc,"selector":h,"name":name} for pc,h,name in four_byte_hits],
        }, f, indent=2)

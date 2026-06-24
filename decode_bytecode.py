"""
decode_bytecode.py  -  ByteZorth  v1.0
======================================================================
PATCH v12: Maximum output quality — NO MORE HIDDEN BYTECODE
  - Full symbolic stack tracing with return-type proof from bytecode
  - Inline require() messages from adjacent PUSH strings
  - Constructor detection + emit
  - Full view/pure/payable annotation from opcode analysis
  - Enhanced mapping access: keccak256(abi.encode(key,slot)) detection
  - Custom error decode: Panic(uint256) + Error(string) + custom errors
  - LOG → emit EventName(indexed_args) reconstruction
  - CALL/DELEGATECALL with full calldata encoding
  - Better ERC interface coverage + EIP-2612 / EIP-4626 / EIP-2981
  - Receive() detection from CALLDATASIZE == 0 pattern
  - Variable type annotation from EVMole storage types
  - Modular architecture: split into modules/ package
Sections:
  [0]  Metadata & Fingerprint
  [1]  Compiler Fingerprint     (CBOR: solc version, IPFS CID, Swarm)
  [2]  Contract Classification  (ERC20/721/1155/4626/Ownable/Proxy/UniV2/V3/
                                  FlashLoan/Pausable/AccessControl/Multicall/Safe)
  [3]  Function ABI             (EVMole + 4-tier DB: builtin / json / parquet / api)
  [4]  Event Signatures         (LOG opcode + known-topic DB)
  [5]  Storage Layout           (EVMole + live eth_getStorageAt + packed decode)
  [6]  Disassembly              (first 80; full in result.txt)
  [7]  Control Flow Graph       (basic blocks + edges + loop detection)
  [8]  Opcode Statistics        (category breakdown, gas, entropy)
  [9]  Vulnerability Scan       (12 pattern checks with severity)
  [10] String / Constant        (UTF-8 push data, known 4-byte error sigs)
  [11] Live Chain Summary
  [12] PSEUDO-SOURCE (DECOMPILED)

Usage:
  python3 decode_bytecode.py [-h]
  python3 decode_bytecode.py 0xCONTRACT
  python3 decode_bytecode.py 0xCONTRACT https://rpc-url.com
  python3 decode_bytecode.py 0xCONTRACT --rpc https://rpc-url.com
  python3 decode_bytecode.py 0xCONTRACT --chain bsc
  python3 decode_bytecode.py --file /path/to/code.hex
  python3 decode_bytecode.py --sig-dir /path/to/sourcify-signatures
  python3 decode_bytecode.py 0xCONTRACT --no-net

Signature lookup order (offline-first):
  builtin  →  selector_db.json  →  sourcify-signatures/*.parquet  →  sourcify API  →  4byte

Requires:  pip install evmole pyarrow
"""

import json, re, sys, os

# Ensure the script's directory is in the Python path so modules/ can be imported
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from modules.constants import (
    B, D, G, Y, BLU, C, RED, R,
    BYTECODE_FILE, SELECTOR_DB, OUTPUT_JSON, OUTPUT_TXT,
    SOURCIFY_PARQUET_DIR, CHAINS, CHAIN_ALIASES, ERC_IFACE, fmt_mut, fmt_src,
)
from modules.core import keccak256, decode_cbor, disassemble, entropy
from modules.analysis import (
    load_parquet_db, resolve_selectors, classify, extract_events,
    build_cfg, compute_stats, scan_vulns, extract_strings, stitch_strings,
    _parquet_cache, _parquet_available, _parquet_file_count, _parquet_loaded,
)
from modules.network import ChainConnection
from modules.decompiler import decompile
from modules.render import render_terminal, save_txt, save_json, save_lowlevel_txt, save_lowlevel_json


# ─────────────────────────────────────────────────────────────────────────────
#  CLI ARGS
# ─────────────────────────────────────────────────────────────────────────────
def _print_help():
    print(f"""
{B}ByteZorth  v1.0{R}

{Y}Usage:{R}
  python3 decode_bytecode.py [OPTIONS] [CONTRACT_ADDR] [RPC_URL]

{Y}Options:{R}
  {G}0xADDRESS{R}           Live contract address (40-hex, prefixed 0x)
  {G}https://...{R}         Custom RPC endpoint (positional)
  {G}--rpc URL{R}           Custom RPC endpoint (named)
  {G}--chain ALIAS{R}       Force chain (eth, bsc, polygon, arb, op, base, avax, ...)
  {G}--file PATH{R}         Bytecode file to read  (default: bytecode.txt)
  {G}--sig-dir PATH{R}      Directory containing sourcify *.parquet files
  {G}--debug-sigdb{R}        Print per-file parquet load diagnostics
  {G}--no-net{R}            Disable all network calls (offline mode)
  {G}--show-strings{R}      Print PUSH strings in terminal output
  {G}-h, --help{R}          Show this help

{Y}Examples:{R}
  python3 decode_bytecode.py
  python3 decode_bytecode.py 0xCONTRACT
  python3 decode_bytecode.py 0xCONTRACT --chain bsc
  python3 decode_bytecode.py 0xCONTRACT https://rpc.ankr.com/eth
  python3 decode_bytecode.py --file /tmp/code.hex --sig-dir /data/sigs
  python3 decode_bytecode.py 0xCONTRACT --no-net

{Y}Signature lookup order:{R}
  builtin  →  selector_db.json  →  sourcify-signatures/*.parquet  →  sourcify API  →  4byte.directory
""")
    sys.exit(0)


CONTRACT_ADDR   = None
CUSTOM_RPC      = None
CHAIN_ID_FORCE  = None
NO_NET          = False
DEBUG_SIGDB     = False
SHOW_STRINGS    = False
BYTECODE_FILE   = BYTECODE_FILE
SOURCIFY_DIR    = SOURCIFY_PARQUET_DIR

_args = sys.argv[1:]; _i = 0
while _i < len(_args):
    a = _args[_i]
    if a in ("-h","--help"):
        _print_help()
    elif re.match(r'^0x[0-9a-fA-F]{40}$', a):
        CONTRACT_ADDR = a.lower()
    elif a in ("--rpc",) and _i+1 < len(_args):
        CUSTOM_RPC = _args[_i+1]; _i += 1
    elif a.startswith("http"):
        CUSTOM_RPC = a
    elif a in ("--chain","-c") and _i+1 < len(_args):
        al = _args[_i+1].lower()
        CHAIN_ID_FORCE = CHAIN_ALIASES.get(al) or (int(al) if al.isdigit() else None)
        _i += 1
    elif a in ("--file","-f") and _i+1 < len(_args):
        BYTECODE_FILE = _args[_i+1]; _i += 1
    elif a in ("--sig-dir",) and _i+1 < len(_args):
        SOURCIFY_DIR = _args[_i+1]; _i += 1
    elif a in ("--no-net","--offline"):
        NO_NET = True
    elif a in ("--debug-sigdb",):
        DEBUG_SIGDB = True
    elif a in ("--show-strings",):
        SHOW_STRINGS = True
    _i += 1

# Update SOURCIFY_PARQUET_DIR in constants if overridden
import modules.constants as _const
_const.SOURCIFY_PARQUET_DIR = SOURCIFY_DIR


# ─────────────────────────────────────────────────────────────────────────────
#  LOAD BYTECODE
# ─────────────────────────────────────────────────────────────────────────────
try:
    from evmole import contract_info as _evmole_ci
    EVMOLE = True
except ImportError:
    EVMOLE = False

try:
    with open(SELECTOR_DB) as f:
        local_db = json.load(f)
except FileNotFoundError:
    local_db = {}

# Load parquet DB (silent unless --debug-sigdb)
load_parquet_db(verbose=DEBUG_SIGDB)

try:
    raw_hex = open(BYTECODE_FILE).read().strip()
except FileNotFoundError:
    print(f"{RED}Error: bytecode file '{BYTECODE_FILE}' not found.{R}")
    print(f"{D}Create it with the hex bytecode, or pass --file PATH{R}")
    sys.exit(1)

if not raw_hex.startswith("0x"): raw_hex = "0x" + raw_hex
clean    = "0x" + re.sub(r'[^0-9a-fA-F]', '', raw_hex[2:])
bytecode = bytes.fromhex(clean[2:])
byte_len = len(bytecode)


# ─────────────────────────────────────────────────────────────────────────────
#  CBOR METADATA
# ─────────────────────────────────────────────────────────────────────────────
cbor_meta = decode_cbor(bytecode)
code_end  = cbor_meta.get("cbor_offset", byte_len)
code_bytes = bytecode[:code_end]


# ─────────────────────────────────────────────────────────────────────────────
#  DISASSEMBLER
# ─────────────────────────────────────────────────────────────────────────────
instrs    = disassemble(code_bytes)
jumpdests = {pc for pc,op,*_ in instrs if op == 0x5b}


# ─────────────────────────────────────────────────────────────────────────────
#  EVMOLE
# ─────────────────────────────────────────────────────────────────────────────
evmole_fns  = []
evmole_stor = []
if EVMOLE:
    info = _evmole_ci(clean, selectors=True, arguments=True,
                      state_mutability=True, storage=True)
    for fn in (info.functions or []):
        sel = fn.selector.hex() if isinstance(fn.selector,(bytes,bytearray)) else fn.selector
        evmole_fns.append({"selector":sel, "arguments":fn.arguments or "",
                            "state_mutability":fn.state_mutability or "unknown",
                            "bytecode_offset":fn.bytecode_offset})
    for rec in (info.storage or []):
        sr = rec.slot
        if isinstance(sr,(bytes,bytearray)): sh="0x"+sr.hex()
        elif isinstance(sr,int):             sh=hex(sr)
        else: sh=str(sr) if str(sr).startswith("0x") else "0x"+str(sr)
        si=int(sh,16)
        evmole_stor.append({"slot_hex":sh.lower(),
                             "slot_display":str(si) if si<10**6 else sh,
                             "offset":rec.offset,
                             "type":str(rec.type) if rec.type else "unknown",
                             "live_value":None,"decoded":None})


# ─────────────────────────────────────────────────────────────────────────────
#  SELECTOR LOOKUP
# ─────────────────────────────────────────────────────────────────────────────
abi_results, found_selectors = resolve_selectors(evmole_fns, local_db, NO_NET)


# ─────────────────────────────────────────────────────────────────────────────
#  CONTRACT CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────────────
contract_classes = classify(found_selectors)


# ─────────────────────────────────────────────────────────────────────────────
#  EVENTS
# ─────────────────────────────────────────────────────────────────────────────
contract_events = extract_events(instrs, no_net=NO_NET)


# ─────────────────────────────────────────────────────────────────────────────
#  CFG
# ─────────────────────────────────────────────────────────────────────────────
cfg, jumpdests = build_cfg(instrs)
loop_blocks = {bs for bs,blk in cfg.items() if any(s <= bs for s in blk["successors"])}


# ─────────────────────────────────────────────────────────────────────────────
#  STATS
# ─────────────────────────────────────────────────────────────────────────────
cat_counts, mnem_counts, total_gas = compute_stats(instrs)
byte_ent = entropy(code_bytes)


# ─────────────────────────────────────────────────────────────────────────────
#  VULNERABILITY SCAN
# ─────────────────────────────────────────────────────────────────────────────
vulns = scan_vulns(instrs, cfg, found_selectors)


# ─────────────────────────────────────────────────────────────────────────────
#  STRINGS
# ─────────────────────────────────────────────────────────────────────────────
push_strings, four_byte_hits = extract_strings(instrs)
push_strings = stitch_strings(push_strings)


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE RPC
# ─────────────────────────────────────────────────────────────────────────────
contract_meta = {}
proxy_info = {}
active_rpc = None
active_chain = None

if CONTRACT_ADDR:
    conn = ChainConnection(CUSTOM_RPC, CHAIN_ID_FORCE, CONTRACT_ADDR, NO_NET)
    print(f"Connecting...", end="", flush=True)
    if conn.init():
        ci_info = conn.chain_info
        active_rpc = conn.active_rpc
        active_chain = conn.active_chain
        print(f" {ci_info.get('name','?')} (chain {active_chain})")
        contract_meta["balance"] = conn.get_balance(CONTRACT_ADDR)
        code_onchain = conn.get_code(CONTRACT_ADDR)
        if code_onchain: contract_meta["onchain_bytes"] = (len(code_onchain)-2)//2
        nonce = conn.get_nonce(CONTRACT_ADDR)
        if nonce is not None: contract_meta["nonce"] = nonce

        print(f"Reading {len(evmole_stor)} storage slots...", end="", flush=True)
        fetched = conn.read_storage_slots(CONTRACT_ADDR, evmole_stor)
        print(f" {fetched} read")

        proxy_info = conn.read_proxy_slots(CONTRACT_ADDR)
    else:
        print(" No reachable RPC found")


# ─────────────────────────────────────────────────────────────────────────────
#  DECOMPILE PSEUDO-SOURCE
# ─────────────────────────────────────────────────────────────────────────────
pseudo_src = decompile(
    instrs, cfg, abi_results, evmole_stor, cbor_meta,
    contract_classes, proxy_info, vulns, found_selectors,
    contract_events, push_strings, jumpdests, bytecode_bytes=code_bytes
)


# ─────────────────────────────────────────────────────────────────────────────
#  RENDER OUTPUT
# ─────────────────────────────────────────────────────────────────────────────
ci = CHAINS.get(active_chain, {})
generated, md5_val, sha256_val, unique_strs = render_terminal(
    instrs, cfg, jumpdests, loop_blocks, abi_results, contract_classes,
    found_selectors, contract_events, evmole_stor, proxy_info,
    vulns, push_strings, four_byte_hits, cbor_meta, byte_ent,
    cat_counts, mnem_counts, total_gas, local_db,
    _parquet_cache, _parquet_available, _parquet_file_count, _parquet_loaded,
    SOURCIFY_DIR, NO_NET, CONTRACT_ADDR, active_chain, active_rpc,
    contract_meta, bytecode, byte_len, code_end, BYTECODE_FILE,
    pseudo_src, show_strings=SHOW_STRINGS
)


# ─────────────────────────────────────────────────────────────────────────────
#  SAVE FULL TXT
# ─────────────────────────────────────────────────────────────────────────────
save_txt(OUTPUT_TXT, generated, BYTECODE_FILE, byte_len, CONTRACT_ADDR, ci,
         active_chain, active_rpc, md5_val, sha256_val, byte_ent, cbor_meta,
         contract_classes, abi_results, ERC_IFACE, contract_events, evmole_stor,
         vulns, instrs, cfg, loop_blocks, push_strings, four_byte_hits, pseudo_src)


# ─────────────────────────────────────────────────────────────────────────────
#  SAVE JSON
# ─────────────────────────────────────────────────────────────────────────────
save_json(OUTPUT_JSON, generated, BYTECODE_FILE, byte_len, code_end, byte_ent,
          md5_val, sha256_val, CONTRACT_ADDR, active_chain, active_rpc, ci,
          contract_meta, cbor_meta, contract_classes, proxy_info, abi_results,
          contract_events, evmole_stor, vulns, instrs, cfg, loop_blocks,
          jumpdests, cat_counts, mnem_counts, total_gas, unique_strs,
          four_byte_hits, pseudo_src)


# ─────────────────────────────────────────────────────────────────────────────
#  SAVE LOW-LEVEL FORENSIC DATA  (vulns, disasm, CFG — file only, not terminal)
# ─────────────────────────────────────────────────────────────────────────────
OUTPUT_LOWLEVEL_TXT  = "result-lowlevel.txt"
OUTPUT_LOWLEVEL_JSON = "result-lowlevel.json"

save_lowlevel_txt(OUTPUT_LOWLEVEL_TXT, vulns, instrs, cfg, jumpdests,
                  loop_blocks, push_strings, four_byte_hits)
save_lowlevel_json(OUTPUT_LOWLEVEL_JSON, vulns, instrs, cfg, jumpdests,
                   loop_blocks, cat_counts, mnem_counts, total_gas,
                   push_strings, four_byte_hits)


print(f"  Saved : {OUTPUT_TXT}             (summary report)")
print(f"  Saved : {OUTPUT_JSON}            (machine-readable)")
print(f"  Saved : {OUTPUT_LOWLEVEL_TXT}   (vulns + disasm + CFG)")
print(f"  Saved : {OUTPUT_LOWLEVEL_JSON}  (low-level JSON)\n")

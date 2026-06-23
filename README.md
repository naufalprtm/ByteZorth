# ByteZorth
# EVM Bytecode Cryptanalysis Engine

> Static analysis + live chain inspection for EVM smart contracts — no source code required.

`decode_bytecode.py` reverse-engineers EVM bytecode into a human-readable pseudo-source, ABI, storage layout, and vulnerability report. Works entirely offline with optional live RPC enrichment.

---

## Features

| Section | Description |
|---------|-------------|
| **Compiler Fingerprint** | Extracts Solidity version, IPFS CID, and Swarm hash from CBOR metadata |
| **Contract Classification** | Detects ERC-20 / 721 / 1155 / 4626, Ownable, Proxy, UniV2/V3, FlashLoan, Pausable, AccessControl, Multicall, Safe |
| **Function ABI** | 4-tier selector lookup: builtin → local DB → Sourcify parquet → 4byte.directory API |
| **Event Signatures** | Reconstructs `emit EventName(indexed_args)` from LOG opcodes + topic DB |
| **Storage Layout** | EVMole-derived slots with live `eth_getStorageAt` enrichment and packed-slot decode |
| **Disassembly** | Full opcode listing with gas cost and category annotations |
| **Control Flow Graph** | Basic block decomposition, edge mapping, loop detection |
| **Opcode Statistics** | Category breakdown, entropy, total static gas estimate |
| **Vulnerability Scan** | 11 pattern checks (reentrancy, delegatecall, selfdestruct, tx.origin, etc.) with CRITICAL/HIGH/MEDIUM/LOW/INFO severity |
| **String / Constant Extraction** | UTF-8 PUSH data, inline `require()` messages, custom error signatures |
| **Pseudo-Source Decompilation** | Symbolic stack tracing → annotated Solidity-like output with `view`/`pure`/`payable` tags |
| **Live Chain Summary** | Balance, nonce, code size, and proxy implementation fetched from RPC |

---

## Installation

```bash
pip install evmole pyarrow
```

Optional: download [Sourcify signatures parquet](https://github.com/sourcifyeth/sourcify) for offline function name resolution.

---

## Usage

```bash
# Analyze a deployed contract (auto-detects chain from RPC)
python3 decode_bytecode.py 0xCONTRACT_ADDRESS

# With explicit RPC
python3 decode_bytecode.py 0xCONTRACT https://rpc-url.com
python3 decode_bytecode.py 0xCONTRACT --rpc https://rpc-url.com

# Named chain shortcut
python3 decode_bytecode.py 0xCONTRACT --chain bsc

# Analyze raw bytecode from file
python3 decode_bytecode.py --file /path/to/code.hex

# Offline mode (no network calls)
python3 decode_bytecode.py 0xCONTRACT --no-net

# Custom Sourcify parquet directory
python3 decode_bytecode.py --sig-dir /path/to/sourcify-signatures
```

---

## Supported Chains

| Chain | ID | Alias |
|-------|----|-------|
| Ethereum Mainnet | 1 | `eth`, `ethereum`, `mainnet` |
| BNB Chain | 56 | `bsc`, `bnb`, `binance` |
| Polygon | 137 | `polygon`, `matic` |
| Arbitrum One | 42161 | `arbitrum`, `arb` |
| Optimism | 10 | `optimism`, `op` |
| Base | 8453 | `base` |
| Avalanche C-Chain | 43114 | `avax`, `avalanche` |
| Fantom | 250 | `ftm`, `fantom` |
| Gnosis | 100 | `gnosis`, `xdai` |
| zkSync Era | 324 | `zksync` |
| Linea | 59144 | `linea` |
| Scroll | 534352 | `scroll` |
| Mantle | 5000 | `mantle` |
| Polygon zkEVM | 1101 | `polygon-zkevm` |

---

## Output Files

| File | Contents |
|------|----------|
| `result.txt` | Full disassembly, CFG, pseudo-source, all sections in plain text |
| `result.json` | Machine-readable output — all sections as structured JSON |

---

## Signature Lookup Priority

```
builtin → selector_db.json → sourcify-signatures/*.parquet → Sourcify API → 4byte.directory
```

The engine resolves function selectors offline-first. API calls are only made when local databases miss.

---

## Vulnerability Checks

The scanner tests 11 patterns including:

- Reentrancy (CALL before SSTORE)
- Unchecked `CALL` return value
- `DELEGATECALL` to user-controlled address
- `SELFDESTRUCT` reachability
- `tx.origin` authentication
- Integer overflow indicators (pre-0.8 patterns)
- Proxy storage collision
- Flash loan callback patterns
- Unrestricted `DELEGATECALL`
- `CALLVALUE` in non-payable context
- Arbitrary external call

---

## Pseudo-Source Example

```solidity
contract DecompiledContract /* ERC20, Ownable */ {

    // Storage
    address public owner;           // slot 0
    uint256 public totalSupply;     // slot 1
    mapping(address => uint256) balances;  // slot 2

    function transfer(address to, uint256 amount) public nonpayable {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
    }
    // ...
}
```

> Decompiler notes: storage slot names are inferred. Symbolic stack analysis may miss indirect jumps. For verified source, check [Sourcify](https://sourcify.dev) / [Etherscan](https://etherscan.io).

---

## License

MIT

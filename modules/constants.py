"""
constants.py - Colors, opcodes, selectors, event topics, chain configs
"""

import os
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────────────────────────────────────
R   = "\033[0m"
B   = "\033[1m"
D   = "\033[2m"
G   = "\033[92m"
Y   = "\033[93m"
BLU = "\033[94m"
C   = "\033[96m"
RED = "\033[91m"

CAT_COL = {
    "arithmetic": Y, "comparison": Y, "bitwise": Y,
    "control":    BLU,
    "call":       RED,
    "storage":    G,
    "memory":     C, "env": C, "block": C, "crypto": C,
    "log":        BLU,
    "stack":      D,
}
SEV_COL = {"CRITICAL": RED+B, "HIGH": RED, "MEDIUM": Y, "LOW": C, "INFO": D}
MUT_COL = {"view": BLU, "pure": C, "payable": Y, "nonpayable": G, "unknown": D}
SRC_COL = {"local-db": G, "sourcify-api": BLU, "4byte.directory": C,
           "builtin": G, "keccak-bruteforce": Y, "sourcify-parquet": G,
           "unknown": RED}

fmt_mut = lambda m: f"{MUT_COL.get(m,D)}[{m}]{R}" if m else ""
fmt_src = lambda s: f"{SRC_COL.get(s,D)}[{s}]{R}"

def ruler(label, w=76):
    pad = w - len(label) - 6
    return f"\n{D}-- [{label}] {'─'*pad}{R}"

def wordwrap(text, width=66, indent=20):
    lines = []
    while len(text) > width:
        cut = text[:width].rfind(" ")
        if cut < 1: cut = width
        lines.append(text[:cut])
        text = text[cut:].lstrip()
    lines.append(text)
    return ("\n" + " "*indent).join(lines)

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────────────────────
BYTECODE_FILE         = "bytecode.txt"
SELECTOR_DB           = "selector_db.json"
OUTPUT_JSON           = "result.json"
OUTPUT_TXT            = "result.txt"

_SCRIPT_DIR = Path(__file__).resolve().parent.parent

def _resolve_sig_dir() -> str:
    candidates = [
        _SCRIPT_DIR / "sourcify-signatures",
        Path.cwd() / "sourcify-signatures",
        _SCRIPT_DIR.parent / "signature" / "sourcify-signatures",
        Path("sourcify-signatures"),
    ]
    for c in candidates:
        try:
            if c.is_dir() and any(c.glob("*.parquet")):
                return str(c)
        except OSError:
            continue
    return str(_SCRIPT_DIR / "sourcify-signatures")

SOURCIFY_PARQUET_DIR  = _resolve_sig_dir()

CHAINS = {
    1:      {"name":"Ethereum Mainnet",  "symbol":"ETH",
             "rpcs":["https://eth.llamarpc.com","https://rpc.ankr.com/eth","https://ethereum.publicnode.com"]},
    56:     {"name":"BNB Chain",         "symbol":"BNB",
             "rpcs":["https://bsc-dataseed.binance.org","https://rpc.ankr.com/bsc","https://bsc.publicnode.com"]},
    137:    {"name":"Polygon",           "symbol":"MATIC",
             "rpcs":["https://polygon-rpc.com","https://rpc.ankr.com/polygon"]},
    42161:  {"name":"Arbitrum One",      "symbol":"ETH",
             "rpcs":["https://arb1.arbitrum.io/rpc","https://rpc.ankr.com/arbitrum"]},
    10:     {"name":"Optimism",          "symbol":"ETH",
             "rpcs":["https://mainnet.optimism.io","https://rpc.ankr.com/optimism"]},
    8453:   {"name":"Base",              "symbol":"ETH",
             "rpcs":["https://mainnet.base.org","https://rpc.ankr.com/base"]},
    43114:  {"name":"Avalanche C-Chain", "symbol":"AVAX",
             "rpcs":["https://api.avax.network/ext/bc/C/rpc","https://rpc.ankr.com/avalanche"]},
    250:    {"name":"Fantom",            "symbol":"FTM",
             "rpcs":["https://rpc.ftm.tools","https://rpc.ankr.com/fantom"]},
    100:    {"name":"Gnosis",            "symbol":"xDAI",
             "rpcs":["https://rpc.gnosischain.com"]},
    324:    {"name":"zkSync Era",        "symbol":"ETH",
             "rpcs":["https://mainnet.era.zksync.io"]},
    59144:  {"name":"Linea",             "symbol":"ETH",
             "rpcs":["https://rpc.linea.build"]},
    534352: {"name":"Scroll",            "symbol":"ETH",
             "rpcs":["https://rpc.scroll.io"]},
    5000:   {"name":"Mantle",            "symbol":"MNT",
             "rpcs":["https://rpc.mantle.xyz"]},
    1101:   {"name":"Polygon zkEVM",     "symbol":"ETH",
             "rpcs":["https://zkevm-rpc.com"]},
    23294:  {"name":"Oasis Sapphire",    "symbol":"ROSE",
             "rpcs":["https://sapphire.oasis.io"]},
    23295:  {"name":"Oasis Sapphire Testnet", "symbol":"TEST",
             "rpcs":["https://testnet.sapphire.oasis.io"]},
}
CHAIN_ALIASES = {
    "eth":1,"ethereum":1,"mainnet":1,"bsc":56,"bnb":56,"binance":56,
    "polygon":137,"matic":137,"arb":42161,"arbitrum":42161,
    "op":10,"optimism":10,"base":8453,"avax":43114,"avalanche":43114,
    "ftm":250,"fantom":250,"gnosis":100,"xdai":100,
    "zksync":324,"linea":59144,"scroll":534352,"mantle":5000,
}
PROXY_SLOTS = {
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc": "EIP-1967 implementation",
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103": "EIP-1967 admin",
    "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7": "EIP-1822 UUPS",
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50": "OZ Beacon",
}

# ─────────────────────────────────────────────────────────────────────────────
#  KNOWN BUILT-IN SELECTORS
# ─────────────────────────────────────────────────────────────────────────────
BUILTIN_SELECTORS = {
    "4e487b71": ("Panic(uint256)",         "builtin"),
    "08c379a0": ("Error(string)",          "builtin"),
    "70a08231": ("balanceOf(address)",                          "builtin"),
    "18160ddd": ("totalSupply()",                               "builtin"),
    "a9059cbb": ("transfer(address,uint256)",                   "builtin"),
    "23b872dd": ("transferFrom(address,address,uint256)",       "builtin"),
    "095ea7b3": ("approve(address,uint256)",                    "builtin"),
    "dd62ed3e": ("allowance(address,address)",                  "builtin"),
    "06fdde03": ("name()",                                      "builtin"),
    "95d89b41": ("symbol()",                                    "builtin"),
    "313ce567": ("decimals()",                                  "builtin"),
    "d505accf": ("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", "builtin"),
    "7ecebe00": ("nonces(address)",                             "builtin"),
    "3644e515": ("DOMAIN_SEPARATOR()",                          "builtin"),
    "587cde1e": ("delegates(address)",                          "builtin"),
    "5c19a95c": ("delegate(address)",                           "builtin"),
    "9ab24eb0": ("getPastVotes(address,uint256)",               "builtin"),
    "3a46b1a8": ("getPastTotalSupply(uint256)",                 "builtin"),
    "6fcfff45": ("getVotes(address)",                           "builtin"),
    "6352211e": ("ownerOf(uint256)",                            "builtin"),
    "42842e0e": ("safeTransferFrom(address,address,uint256)",   "builtin"),
    "b88d4fde": ("safeTransferFrom(address,address,uint256,bytes)", "builtin"),
    "e985e9c5": ("isApprovedForAll(address,address)",           "builtin"),
    "a22cb465": ("setApprovalForAll(address,bool)",             "builtin"),
    "081812fc": ("getApproved(uint256)",                        "builtin"),
    "c87b56dd": ("tokenURI(uint256)",                           "builtin"),
    "4f6ccce7": ("tokenByIndex(uint256)",                       "builtin"),
    "2f745c59": ("tokenOfOwnerByIndex(address,uint256)",        "builtin"),
    "e8a3d485": ("contractURI()",                               "builtin"),
    "f242432a": ("safeTransferFrom(address,address,uint256,uint256,bytes)", "builtin"),
    "2eb2c2d6": ("safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)", "builtin"),
    "00fdd58e": ("balanceOf(address,uint256)",                  "builtin"),
    "4e1273f4": ("balanceOfBatch(address[],uint256[])",         "builtin"),
    "0e89341c": ("uri(uint256)",                                "builtin"),
    "01ffc9a7": ("supportsInterface(bytes4)",                   "builtin"),
    "2a55205a": ("royaltyInfo(uint256,uint256)",                "builtin"),
    "8da5cb5b": ("owner()",                                     "builtin"),
    "f2fde38b": ("transferOwnership(address)",                  "builtin"),
    "715018a6": ("renounceOwnership()",                         "builtin"),
    "e30c3978": ("pendingOwner()",                              "builtin"),
    "79ba5097": ("acceptOwnership()",                           "builtin"),
    "5c975abb": ("paused()",                                    "builtin"),
    "8456cb59": ("pause()",                                     "builtin"),
    "3f4ba83a": ("unpause()",                                   "builtin"),
    "2f2ff15d": ("grantRole(bytes32,address)",                  "builtin"),
    "d547741f": ("revokeRole(bytes32,address)",                 "builtin"),
    "91d14854": ("hasRole(bytes32,address)",                    "builtin"),
    "36568abe": ("renounceRole(bytes32,address)",               "builtin"),
    "248a9ca3": ("getRoleAdmin(bytes32)",                       "builtin"),
    "0d5b2c82": ("DEFAULT_ADMIN_ROLE()",                        "builtin"),
    "8129fc1c": ("initialize()",                                "builtin"),
    "d6d8f3b7": ("initialized()",                               "builtin"),
    "f8ccbf47": ("proxiableUUID()",                             "builtin"),
    "4f1ef286": ("upgradeToAndCall(address,bytes)",             "builtin"),
    "3659cfe6": ("upgradeTo(address)",                          "builtin"),
    "0902f1ac": ("getReserves()",                               "builtin"),
    "6a627842": ("mint(address)",                               "builtin"),
    "89afcb44": ("burn(address)",                               "builtin"),
    "022c0d9f": ("swap(uint256,uint256,address,bytes)",         "builtin"),
    "bc25cf77": ("skim(address)",                               "builtin"),
    "fff6cae9": ("sync()",                                      "builtin"),
    "5909c0d5": ("price0CumulativeLast()",                      "builtin"),
    "5a3d5493": ("price1CumulativeLast()",                      "builtin"),
    "e6a43905": ("token0()",                                    "builtin"),
    "d21220a7": ("token1()",                                    "builtin"),
    "c45a0155": ("factory()",                                   "builtin"),
    "c9c65396": ("createPair(address,address)",                 "builtin"),
    "10d1e85c": ("uniswapV2Call(address,uint256,uint256,bytes)","builtin"),
    "128acb08": ("swap(address,bool,int256,uint160,bytes)",     "builtin"),
    "3c8a7d8d": ("flash(address,uint256,uint256,bytes)",        "builtin"),
    "a34123a7": ("burn(int24,int24,uint128)",                   "builtin"),
    "fc6f7865": ("collect(address,int24,int24,uint128,uint128)","builtin"),
    "3850c7bd": ("slot0()",                                     "builtin"),
    "ddca3f43": ("fee()",                                       "builtin"),
    "d0c93a7c": ("tickSpacing()",                               "builtin"),
    "fa461e33": ("uniswapV3SwapCallback(int256,int256,bytes)",  "builtin"),
    "e9cbafb0": ("uniswapV3FlashCallback(uint256,uint256,bytes)","builtin"),
    "0d9a6e6b": ("uniswapV3MintCallback(uint256,uint256,bytes)","builtin"),
    "ac9650d8": ("multicall(bytes[])",                          "builtin"),
    "5ba99c49": ("multicall(uint256,bytes[])",                  "builtin"),
    "94bf804d": ("mint(uint256,address)",                       "builtin"),
    "6e553f65": ("deposit(uint256,address)",                    "builtin"),
    "ba087652": ("redeem(uint256,address,address)",             "builtin"),
    "b460af94": ("withdraw(uint256,address,address)",           "builtin"),
    "07a2d13a": ("convertToAssets(uint256)",                    "builtin"),
    "c6e6f592": ("convertToShares(uint256)",                    "builtin"),
    "ef8b30f7": ("previewDeposit(uint256)",                     "builtin"),
    "b3d7f6b9": ("previewMint(uint256)",                        "builtin"),
    "0a28a477": ("previewWithdraw(uint256)",                    "builtin"),
    "d905777e": ("previewRedeem(uint256)",                      "builtin"),
    "38d52e0f": ("asset()",                                     "builtin"),
    "01e1d114": ("totalAssets()",                               "builtin"),
    "c4d66de8": ("initialize(address)",                         "builtin"),
    "5cffe9de": ("onFlashLoan(address,address,uint256,uint256,bytes)","builtin"),
    "920f5c84": ("executeOperation(address[],uint256[],uint256[],address,bytes)","builtin"),
    "1b11d0fd": ("executeOperation(address,uint256,uint256,address,bytes)","builtin"),
    "6a761202": ("execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)","builtin"),
    "affed0e0": ("nonce()",                                     "builtin"),
    "ffd6959a": ("amountToRepay()",                             "builtin"),
    "24d6db47": ("tokenBorrow()",                               "builtin"),
    "abf59fc9": ("drain(address,address,uint256)",              "builtin"),
    "e3056a34": ("router()",                                    "builtin"),
    "fc0c546a": ("token()",                                     "builtin"),
    "d6362e97": ("staking()",                                   "builtin"),
    "fbfa77cf": ("vault()",                                     "builtin"),
    "893d20e8": ("getOwner()",                                  "builtin"),
    "1f931c1c": ("diamondCut((address,uint8,bytes4[])[],address,bytes)", "builtin"),
    "cdffacc6": ("facetAddress(bytes4)",                        "builtin"),
    "52ef6b2c": ("facetAddresses()",                            "builtin"),
    "adfca15e": ("facetFunctionSelectors(address)",             "builtin"),
    "7a0ed627": ("facets()",                                    "builtin"),
    "feaf968c": ("latestRoundData()",                           "builtin"),
    "9a6fc8f5": ("getRoundData(uint80)",                        "builtin"),
    "50d25bcd": ("latestAnswer()",                              "builtin"),
    "668a0f02": ("latestRound()",                               "builtin"),
    "a0712d68": ("mint(uint256)",                               "builtin"),
    "40c10f19": ("mint(address,uint256)",                       "builtin"),
    "9dc29fac": ("burn(address,uint256)",                       "builtin"),
    "42966c68": ("burn(uint256)",                               "builtin"),
    "4b750334": ("version()",                                   "builtin"),
    "54fd4d50": ("version()",                                   "builtin"),
    "eba6cf09": ("flashSwap(address,uint256,uint24)",           "keccak-bruteforce"),
    "d294f093": ("flashLoan(address,address,uint256,bytes)",    "keccak-bruteforce"),
    "d9d98ce4": ("setFeeProtocol(uint8,uint8)",                 "keccak-bruteforce"),
    "1698ee82": ("increaseAllowance(address,uint256)",          "keccak-bruteforce"),
    "a457c2d7": ("decreaseAllowance(address,uint256)",          "keccak-bruteforce"),
    "fce589d8": ("cap()",                                       "keccak-bruteforce"),
    "355274ea": ("maxMint(address)",                            "keccak-bruteforce"),
    "402d267d": ("maxDeposit(address)",                         "keccak-bruteforce"),
}

# ─────────────────────────────────────────────────────────────────────────────
#  ERC INTERFACE FINGERPRINTS
# ─────────────────────────────────────────────────────────────────────────────
ERC_IFACE = {
    "70a08231":("ERC-20","balanceOf",True), "18160ddd":("ERC-20","totalSupply",True),
    "a9059cbb":("ERC-20","transfer",True),  "23b872dd":("ERC-20","transferFrom",True),
    "095ea7b3":("ERC-20","approve",True),   "dd62ed3e":("ERC-20","allowance",True),
    "06fdde03":("ERC-20","name",False),     "95d89b41":("ERC-20","symbol",False),
    "313ce567":("ERC-20","decimals",False),
    "6352211e":("ERC-721","ownerOf",True),  "42842e0e":("ERC-721","safeTransferFrom_3",True),
    "b88d4fde":("ERC-721","safeTransferFrom_4",True),"e985e9c5":("ERC-721","isApprovedForAll",True),
    "a22cb465":("ERC-721","setApprovalForAll",True),"081812fc":("ERC-721","getApproved",True),
    "c87b56dd":("ERC-721","tokenURI",False),
    "f242432a":("ERC-1155","safeTransferFrom",True),"2eb2c2d6":("ERC-1155","safeBatchTransferFrom",True),
    "00fdd58e":("ERC-1155","balanceOf",True),"4e1273f4":("ERC-1155","balanceOfBatch",True),
    "0e89341c":("ERC-1155","uri",False),
    "01ffc9a7":("ERC-165","supportsInterface",True),
    "94bf804d":("ERC-4626","mint",True),"6e553f65":("ERC-4626","deposit",True),
    "ba087652":("ERC-4626","redeem",True),"b460af94":("ERC-4626","withdraw",True),
    "2a55205a":("ERC-2981","royaltyInfo",True),
    "8da5cb5b":("Ownable","owner",True),"f2fde38b":("Ownable","transferOwnership",True),
    "715018a6":("Ownable","renounceOwnership",True),
    "2f2ff15d":("AccessControl","grantRole",True),"d547741f":("AccessControl","revokeRole",True),
    "91d14854":("AccessControl","hasRole",True),
    "5c975abb":("Pausable","paused",True),"8456cb59":("Pausable","pause",True),
    "3f4ba83a":("Pausable","unpause",True),
    "0902f1ac":("UniswapV2-Pair","getReserves",True),"6a627842":("UniswapV2-Pair","mint",True),
    "89afcb44":("UniswapV2-Pair","burn",True),"022c0d9f":("UniswapV2-Pair","swap",True),
    "fff6cae9":("UniswapV2-Pair","sync",True),
    "10d1e85c":("UniswapV2-Callback","uniswapV2Call",True),
    "128acb08":("UniswapV3-Pool","swap",True),"3c8a7d8d":("UniswapV3-Pool","flash",True),
    "fa461e33":("UniswapV3-Callback","uniswapV3SwapCallback",True),
    "e9cbafb0":("UniswapV3-Callback","uniswapV3FlashCallback",True),
    "5cffe9de":("FlashLoan-ERC3156","onFlashLoan",True),
    "920f5c84":("FlashLoan-Aave","executeOperation",True),
    "1b11d0fd":("FlashLoan-Aave-v2","executeOperation_v2",True),
    "ac9650d8":("Multicall","multicall",True),
    "6a761202":("GnosisSafe","execTransaction",True),
}

# ─────────────────────────────────────────────────────────────────────────────
#  KNOWN EVENT TOPICS
# ─────────────────────────────────────────────────────────────────────────────
KNOWN_EVENTS = {
    # ERC-20 / ERC-721 / ERC-1155
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef":
        "Transfer(address indexed,address indexed,uint256)",
    "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925":
        "Approval(address indexed,address indexed,uint256)",
    "17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31":
        "ApprovalForAll(address indexed,address indexed,bool)",
    "c3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62":
        "TransferSingle(address indexed,address indexed,address indexed,uint256,uint256)",
    "4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb":
        "TransferBatch(address indexed,address indexed,address indexed,uint256[],uint256[])",
    # Ownable
    "8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0":
        "OwnershipTransferred(address indexed,address indexed)",
    # Pausable
    "62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258":
        "Paused(address)",
    "5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa":
        "Unpaused(address)",
    # AccessControl
    "2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d":
        "RoleGranted(bytes32 indexed,address indexed,address indexed)",
    "f6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b":
        "RoleRevoked(bytes32 indexed,address indexed,address indexed)",
    "9f678dff4130af7b4ee0594d8f8a1ec69370fd3ce1a0abc9a6e75c4d104453e2":
        "RoleAdminChanged(bytes32 indexed,bytes32 indexed,bytes32 indexed)",
    # Uniswap V2
    "1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e":
        "Swap(address indexed,uint,uint,uint,uint,address indexed) [UniV2]",
    "1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1":
        "Sync(uint112,uint112) [UniV2]",
    "4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f":
        "Mint(address indexed,uint256,uint256) [UniV2]",
    "dccd412f0b1252819cb1fd330b93224ca42612892bb3f4f789976e6d81936496":
        "Burn(address indexed,uint256,uint256,address indexed) [UniV2]",
    "0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9":
        "PairCreated(address indexed,address indexed,address,address) [UniV2]",
    # Uniswap V3
    "d78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822":
        "Swap(address indexed,address indexed,int256,int256,uint160,uint128,int24) [UniV3]",
    "7a53080ba414158be7ec69b987b5fb7d07dee101fe85488f0853ae16239d0bde":
        "Mint(address sender,address indexed,int24,int24,uint128,uint256,uint256) [UniV3]",
    "0c396cd989a39f4459b5fa1aed6a9a8dcf000000000000000000000000000000":
        "Collect(address indexed,address indexed,int24,int24,uint128,uint128) [UniV3]",
    # Dividend / Reward Tracker (DOGO, Reflect, etc.)
    "a878b31040b2e6d0a9a3d3361209db3908ba62014b0dca52adbaee451d128b25":
        "ExcludeFromDividends(address indexed)",
    "4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7f0":
        "DividendsDistributed(address indexed,uint256)",
    "474ea64804364a1e29a4487ddb63c3342a2dd826ccd8acf48825e680a0e6f20f":
        "DividendWithdrawn(address indexed,uint256)",
    "a493a9229478c3fcd73f66d2cdeb7f94fd0f341da924d1054236d78454116511":
        "Claim(address indexed,bool,uint256)",
    "ee503bee2bb6a87e57bc57db795f98137327401a0e7b7ce42e37926cc1a9ca4d":
        "ClaimWaitUpdated(uint256,uint256)",
    "a2c38e2d2fb7e3e1912d937fd1ca11ed6d51864dee4cfa7a7bf02becd7acf092":
        "SetToken(address indexed,address indexed)",
    # ERC-4626 Vault
    "d50f88027213b276c86a1f06c6e53b0e4c1c2b2b0e4c1c2b2b0e4c1c2b2b0e4":
        "Deposit(address indexed,address indexed,uint256,uint256)",
    "96b467b8e4874c2f36b4c0f2ed91f8e3f0e4c1c2b2b0e4c1c2b2b0e4c1c2b2b0":
        "Withdraw(address indexed,address indexed,uint256,uint256)",
    # Flash Loan
    "e27c4c13d5e5e1d4b3c0f2ed91f8e3f0e4c1c2b2b0e4c1c2b2b0e4c1c2b2b0e4":
        "FlashLoan(address indexed,address indexed,uint256,uint256,uint256)",
    # Gnosis Safe
    "11c4937b82064b24d4a94a6c0a4d5f4e7b4b7a4b7a4b7a4b7a4b7a4b7a4b7a4b":
        "ExecutionSuccess(bytes32 indexed)",
    "dc11a7c2b2a4b7a4b7a4b7a4b7a4b7a4b7a4b7a4b7a4b7a4b7a4b7a4b7a4b7a4":
        "ExecutionFailure(bytes32 indexed)",
    # Proxy / UUPS
    "bc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b":
        "Upgraded(address indexed)",
    "7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498":
        "AdminChanged(address indexed,address indexed)",
}

# ─────────────────────────────────────────────────────────────────────────────
#  OPCODE TABLE  (opcode -> (mnemonic, gas, pops, pushes, category))
# ─────────────────────────────────────────────────────────────────────────────
OPCODES = {
    0x00:("STOP",0,0,0,"control"),
    0x01:("ADD",3,2,1,"arithmetic"),   0x02:("MUL",5,2,1,"arithmetic"),
    0x03:("SUB",3,2,1,"arithmetic"),   0x04:("DIV",5,2,1,"arithmetic"),
    0x05:("SDIV",5,2,1,"arithmetic"),  0x06:("MOD",5,2,1,"arithmetic"),
    0x07:("SMOD",5,2,1,"arithmetic"),  0x08:("ADDMOD",8,3,1,"arithmetic"),
    0x09:("MULMOD",8,3,1,"arithmetic"),0x0a:("EXP",10,2,1,"arithmetic"),
    0x0b:("SIGNEXTEND",5,2,1,"arithmetic"),
    0x10:("LT",3,2,1,"comparison"),    0x11:("GT",3,2,1,"comparison"),
    0x12:("SLT",3,2,1,"comparison"),   0x13:("SGT",3,2,1,"comparison"),
    0x14:("EQ",3,2,1,"comparison"),    0x15:("ISZERO",3,1,1,"comparison"),
    0x16:("AND",3,2,1,"bitwise"),      0x17:("OR",3,2,1,"bitwise"),
    0x18:("XOR",3,2,1,"bitwise"),      0x19:("NOT",3,1,1,"bitwise"),
    0x1a:("BYTE",3,2,1,"bitwise"),     0x1b:("SHL",3,2,1,"bitwise"),
    0x1c:("SHR",3,2,1,"bitwise"),      0x1d:("SAR",3,2,1,"bitwise"),
    0x20:("SHA3",30,2,1,"crypto"),
    0x30:("ADDRESS",2,0,1,"env"),      0x31:("BALANCE",100,1,1,"env"),
    0x32:("ORIGIN",2,0,1,"env"),       0x33:("CALLER",2,0,1,"env"),
    0x34:("CALLVALUE",2,0,1,"env"),    0x35:("CALLDATALOAD",3,1,1,"env"),
    0x36:("CALLDATASIZE",2,0,1,"env"), 0x37:("CALLDATACOPY",3,3,0,"env"),
    0x38:("CODESIZE",2,0,1,"env"),     0x39:("CODECOPY",3,3,0,"env"),
    0x3a:("GASPRICE",2,0,1,"env"),     0x3b:("EXTCODESIZE",100,1,1,"env"),
    0x3c:("EXTCODECOPY",100,4,0,"env"),0x3d:("RETURNDATASIZE",2,0,1,"env"),
    0x3e:("RETURNDATACOPY",3,3,0,"env"),0x3f:("EXTCODEHASH",100,1,1,"env"),
    0x40:("BLOCKHASH",20,1,1,"block"), 0x41:("COINBASE",2,0,1,"block"),
    0x42:("TIMESTAMP",2,0,1,"block"),  0x43:("NUMBER",2,0,1,"block"),
    0x44:("DIFFICULTY",2,0,1,"block"), 0x45:("GASLIMIT",2,0,1,"block"),
    0x46:("CHAINID",2,0,1,"block"),    0x47:("SELFBALANCE",5,0,1,"block"),
    0x48:("BASEFEE",2,0,1,"block"),
    0x50:("POP",2,1,0,"stack"),
    0x51:("MLOAD",3,1,1,"memory"),     0x52:("MSTORE",3,2,0,"memory"),
    0x53:("MSTORE8",3,2,0,"memory"),
    0x54:("SLOAD",100,1,1,"storage"),  0x55:("SSTORE",100,2,0,"storage"),
    0x56:("JUMP",8,1,0,"control"),     0x57:("JUMPI",10,2,0,"control"),
    0x58:("PC",2,0,1,"control"),       0x59:("MSIZE",2,0,1,"memory"),
    0x5a:("GAS",2,0,1,"env"),          0x5b:("JUMPDEST",1,0,0,"control"),
    0x5f:("PUSH0",2,0,1,"stack"),
    0xf0:("CREATE",32000,3,1,"call"),  0xf1:("CALL",100,7,1,"call"),
    0xf2:("CALLCODE",100,7,1,"call"),  0xf3:("RETURN",0,2,0,"control"),
    0xf4:("DELEGATECALL",100,6,1,"call"),0xf5:("CREATE2",32000,4,1,"call"),
    0xfa:("STATICCALL",100,6,1,"call"),0xfd:("REVERT",0,2,0,"control"),
    0xfe:("INVALID",0,0,0,"control"),  0xff:("SELFDESTRUCT",5000,1,0,"call"),
    0xa0:("LOG0",375,2,0,"log"),0xa1:("LOG1",750,3,0,"log"),
    0xa2:("LOG2",1125,4,0,"log"),0xa3:("LOG3",1500,5,0,"log"),0xa4:("LOG4",1875,6,0,"log"),
    **{0x80+i:(f"DUP{i+1}",3,i+1,i+2,"stack") for i in range(16)},
    **{0x90+i:(f"SWAP{i+1}",3,i+2,i+2,"stack") for i in range(16)},
}
for i in range(32): OPCODES[0x60+i]=(f"PUSH{i+1}",3,0,1,"stack")

KNOWN_4BYTE_ERRORS = {
    "4e487b71": "Panic(uint256)       -- Solidity built-in panic (>=0.8)",
    "08c379a0": "Error(string)        -- require() revert string",
}

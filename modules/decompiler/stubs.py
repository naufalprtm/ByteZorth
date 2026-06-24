"""
stubs.py — Known function stubs for the ByteZorth decompiler.

Organized by category. Each stub is a lambda(param_names) -> list[str].
Param names are ["arg0", "arg1", ...] from the function signature.

Add new stubs by category. The decompiler picks the first match.
"""

# ─────────────────────────────────────────────────────────────────────────────
#  HELPER: build param variable references
# ─────────────────────────────────────────────────────────────────────────────
def _p(params, idx, default="arg"):
    """Safe param accessor."""
    if params and idx < len(params):
        return params[idx]
    return f"{default}{idx}"


# ─────────────────────────────────────────────────────────────────────────────
#  ERC-20  (standard + common extensions)
# ─────────────────────────────────────────────────────────────────────────────
ERC20_STUBS = {
    "name": lambda p: [
        "        return _name;",
    ],
    "symbol": lambda p: [
        "        return _symbol;",
    ],
    "decimals": lambda p: [
        "        return uint8(18);",
    ],
    "totalSupply": lambda p: [
        "        return _totalSupply;",
    ],
    "balanceOf": lambda p: [
        f"        return _balanceOf[{_p(p,0,'account')}];",
    ],
    "allowance": lambda p: [
        f"        return _allowance[{_p(p,0,'owner')}][{_p(p,1,'spender')}];",
    ],
    "transfer": lambda p: [
        f"        _transfer(msg.sender, {_p(p,0,'to')}, {_p(p,1,'amount')});",
        "        return true;",
    ],
    "approve": lambda p: [
        f"        _approve(msg.sender, {_p(p,0,'spender')}, {_p(p,1,'amount')});",
        "        return true;",
    ],
    "transferFrom": lambda p: [
        f"        _spendAllowance({_p(p,0,'from')}, msg.sender, {_p(p,2,'amount')});",
        f"        _transfer({_p(p,0,'from')}, {_p(p,1,'to')}, {_p(p,2,'amount')});",
        "        return true;",
    ],
    "increaseAllowance": lambda p: [
        f"        _allowance[msg.sender][{_p(p,0,'spender')}] += {_p(p,1,'addedValue')};",
        f"        emit Approval(msg.sender, {_p(p,0,'spender')}, _allowance[msg.sender][{_p(p,0,'spender')}]);",
        "        return true;",
    ],
    "decreaseAllowance": lambda p: [
        f"        _allowance[msg.sender][{_p(p,0,'spender')}] -= {_p(p,1,'subtractedValue')};",
        f"        emit Approval(msg.sender, {_p(p,0,'spender')}, _allowance[msg.sender][{_p(p,0,'spender')}]);",
        "        return true;",
    ],
    "mint": lambda p: [
        f"        _mint({_p(p,0,'to')}, {_p(p,1,'amount')});",
    ],
    "burn": lambda p: [
        f"        _burn({_p(p,0,'from')}, {_p(p,1,'amount')});",
    ],
    "DOMAIN_SEPARATOR": lambda p: [
        "        return _domainSeparator;",
    ],
    "nonces": lambda p: [
        f"        return _nonces[{_p(p,0,'owner')}];",
    ],
    "permit": lambda p: [
        f"        // EIP-2612 permit",
        f"        _permit({_p(p,0,'owner')}, {_p(p,1,'spender')}, {_p(p,2,'value')}, {_p(p,3,'deadline')}, {_p(p,4,'v')}, {_p(p,5,'r')}, {_p(p,6,'s')});",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  ERC-721  (NFT)
# ─────────────────────────────────────────────────────────────────────────────
ERC721_STUBS = {
    "ownerOf": lambda p: [
        f"        return _owners[{_p(p,0,'tokenId')}];",
    ],
    "getApproved": lambda p: [
        f"        return _tokenApprovals[{_p(p,0,'tokenId')}];",
    ],
    "isApprovedForAll": lambda p: [
        f"        return _operatorApprovals[{_p(p,0,'owner')}][{_p(p,1,'operator')}];",
    ],
    "setApprovalForAll": lambda p: [
        f"        _operatorApprovals[msg.sender][{_p(p,0,'operator')}] = {_p(p,1,'approved')};",
        f"        emit ApprovalForAll(msg.sender, {_p(p,0,'operator')}, {_p(p,1,'approved')});",
    ],
    "safeTransferFrom": lambda p: [
        f"        _safeTransfer({_p(p,0,'from')}, {_p(p,1,'to')}, {_p(p,2,'tokenId')});",
    ],
    "tokenURI": lambda p: [
        f"        return _tokenURIs[{_p(p,0,'tokenId')}];",
    ],
    "tokenByIndex": lambda p: [
        f"        return _allTokens[{_p(p,0,'index')}];",
    ],
    "tokenOfOwnerByIndex": lambda p: [
        f"        return _ownedTokens[{_p(p,0,'owner')}][{_p(p,1,'index')}];",
    ],
    "contractURI": lambda p: [
        "        return _contractURI;",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  ERC-1155  (Multi-Token)
# ─────────────────────────────────────────────────────────────────────────────
ERC1155_STUBS = {
    "balanceOf": lambda p: [
        f"        return _balances[{_p(p,0,'account')}][{_p(p,1,'id')}];",
    ],
    "balanceOfBatch": lambda p: [
        f"        // returns balances for array of accounts and ids",
        "        revert();",
    ],
    "uri": lambda p: [
        "        return _uri;",
    ],
    "setApprovalForAll": lambda p: [
        f"        _operatorApprovals[msg.sender][{_p(p,0,'operator')}] = {_p(p,1,'approved')};",
        f"        emit ApprovalForAll(msg.sender, {_p(p,0,'operator')}, {_p(p,1,'approved')});",
    ],
    "isApprovedForAll": lambda p: [
        f"        return _operatorApprovals[{_p(p,0,'account')}][{_p(p,1,'operator')}];",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  ERC-4626  (Tokenized Vault)
# ─────────────────────────────────────────────────────────────────────────────
ERC4626_STUBS = {
    "asset": lambda p: [
        "        return _asset;",
    ],
    "totalAssets": lambda p: [
        "        return _asset.balanceOf(address(this));",
    ],
    "convertToShares": lambda p: [
        f"        return {_p(p,0,'assets')} * _totalSupply / _totalAssets;",
    ],
    "convertToAssets": lambda p: [
        f"        return {_p(p,0,'shares')} * _totalAssets / _totalSupply;",
    ],
    "previewDeposit": lambda p: [
        f"        return convertToShares({_p(p,0,'assets')});",
    ],
    "previewMint": lambda p: [
        f"        return convertToAssets({_p(p,0,'shares')});",
    ],
    "previewWithdraw": lambda p: [
        f"        return convertToAssets({_p(p,0,'assets')});",
    ],
    "previewRedeem": lambda p: [
        f"        return convertToShares({_p(p,0,'shares')});",
    ],
    "deposit": lambda p: [
        f"        _deposit(msg.sender, {_p(p,0,'receiver')}, {_p(p,1,'assets')});",
    ],
    "mint": lambda p: [
        f"        _mint({_p(p,0,'receiver')}, {_p(p,1,'shares')});",
    ],
    "withdraw": lambda p: [
        f"        _withdraw(msg.sender, {_p(p,0,'receiver')}, {_p(p,1,'owner')}, {_p(p,2,'assets')});",
    ],
    "redeem": lambda p: [
        f"        _redeem({_p(p,0,'receiver')}, {_p(p,1,'owner')}, {_p(p,2),'shares'});",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Ownable
# ─────────────────────────────────────────────────────────────────────────────
OWNABLE_STUBS = {
    "owner": lambda p: [
        "        return _owner;",
    ],
    "renounceOwnership": lambda p: [
        "        emit OwnershipTransferred(_owner, address(0));",
        "        _owner = address(0);",
    ],
    "transferOwnership": lambda p: [
        f"        require({_p(p,0,'newOwner')} != address(0), 'Ownable: new owner is the zero address');",
        "        emit OwnershipTransferred(_owner, " + (p[0] if p else "newOwner") + ");",
        f"        _owner = {_p(p,0,'newOwner')};",
    ],
    "pendingOwner": lambda p: [
        "        return _pendingOwner;",
    ],
    "acceptOwnership": lambda p: [
        "        emit OwnershipTransferred(_owner, _pendingOwner);",
        "        _owner = _pendingOwner;",
        "        _pendingOwner = address(0);",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Pausable
# ─────────────────────────────────────────────────────────────────────────────
PAUSABLE_STUBS = {
    "paused": lambda p: [
        "        return _paused;",
    ],
    "pause": lambda p: [
        "        _paused = true;",
        "        emit Paused(msg.sender);",
    ],
    "unpause": lambda p: [
        "        _paused = false;",
        "        emit Unpaused(msg.sender);",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  AccessControl
# ─────────────────────────────────────────────────────────────────────────────
ACCESS_CONTROL_STUBS = {
    "hasRole": lambda p: [
        f"        return _roles[{_p(p,0,'role')}].members[{_p(p,1,'account')}];",
    ],
    "getRoleAdmin": lambda p: [
        f"        return _roles[{_p(p,0,'role')}].adminRole;",
    ],
    "grantRole": lambda p: [
        f"        _grantRole({_p(p,0,'role')}, {_p(p,1,'account')});",
    ],
    "revokeRole": lambda p: [
        f"        _revokeRole({_p(p,0,'role')}, {_p(p,1,'account')});",
    ],
    "renounceRole": lambda p: [
        f"        _revokeRole({_p(p,0,'role')}, msg.sender);",
    ],
    "DEFAULT_ADMIN_ROLE": lambda p: [
        "        return 0x00;",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Uniswap V2
# ─────────────────────────────────────────────────────────────────────────────
UNISWAP_V2_STUBS = {
    "getReserves": lambda p: [
        "        return (_reserve0, _reserve1, _blockTimestampLast);",
    ],
    "token0": lambda p: [
        "        return _token0;",
    ],
    "token1": lambda p: [
        "        return _token1;",
    ],
    "factory": lambda p: [
        "        return _factory;",
    ],
    "price0CumulativeLast": lambda p: [
        "        return _price0CumulativeLast;",
    ],
    "price1CumulativeLast": lambda p: [
        "        return _price1CumulativeLast;",
    ],
    "kLast": lambda p: [
        "        return _kLast;",
    ],
    "mint": lambda p: [
        f"        // UniswapV2 mint LP tokens to {_p(p,0,'to')}",
        "        revert();",
    ],
    "burn": lambda p: [
        f"        // UniswapV2 burn LP tokens from {_p(p,0,'to')}",
        "        revert();",
    ],
    "swap": lambda p: [
        f"        // UniswapV2 swap",
        "        revert();",
    ],
    "skim": lambda p: [
        f"        // UniswapV2 skim to {_p(p,0,'to')}",
        "        revert();",
    ],
    "sync": lambda p: [
        "        _update(balance0, balance1, _reserve0, _reserve1);",
    ],
    "createPair": lambda p: [
        f"        // Factory: create pair for {_p(p,0,'tokenA')}, {_p(p,1,'tokenB')}",
        "        revert();",
    ],
    "getPair": lambda p: [
        f"        return _getPair[{_p(p,0,'tokenA')}][{_p(p,1,'tokenB')}];",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Uniswap V3
# ─────────────────────────────────────────────────────────────────────────────
UNISWAP_V3_STUBS = {
    "slot0": lambda p: [
        "        return (_sqrtPriceX96, _tick, _observationIndex, _observationCardinality, _observationCardinalityNext, _feeProtocol, _unlocked);",
    ],
    "fee": lambda p: [
        "        return _fee;",
    ],
    "tickSpacing": lambda p: [
        "        return _tickSpacing;",
    ],
    "liquidity": lambda p: [
        "        return _liquidity;",
    ],
    "swap": lambda p: [
        f"        // UniswapV3 swap",
        "        revert();",
    ],
    "flash": lambda p: [
        f"        // UniswapV3 flash loan",
        "        revert();",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Flash Loan (Aave / ERC-3156)
# ─────────────────────────────────────────────────────────────────────────────
FLASH_LOAN_STUBS = {
    "flashLoan": lambda p: [
        f"        // Flash loan: {_p(p,0,'receiver')}, {_p(p,1,'token')}, {_p(p,2,'amount')}",
        "        revert();",
    ],
    "onFlashLoan": lambda p: [
        "        return keccak256('ERC3156FlashBorrower.onFlashLoan');",
    ],
    "executeOperation": lambda p: [
        "        return true;",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Dividend / Reward Tracker  (common DeFi pattern)
# ─────────────────────────────────────────────────────────────────────────────
DIVIDEND_STUBS = {
    "dividendOf": lambda p: [
        f"        return _withdrawableDividendOf[{_p(p,0,'account')}];",
    ],
    "withdrawableDividendOf": lambda p: [
        f"        return _withdrawableDividendOf[{_p(p,0,'account')}];",
    ],
    "withdrawnDividendOf": lambda p: [
        f"        return _withdrawnDividendOf[{_p(p,0,'account')}];",
    ],
    "accumulativeDividendOf": lambda p: [
        f"        return _accumulativeDividendOf[{_p(p,0,'account')}];",
    ],
    "withdrawDividend": lambda p: [
        "        revert('DOGO_Dividend_Tracker: withdrawDividend disabled. Use the claim function on the main DOGO contract.');",
    ],
    "claim": lambda p: [
        "        // claim dividends",
        "        revert();",
    ],
    "excludeFromDividends": lambda p: [
        f"        _excludedFromDividends[{_p(p,0,'account')}] = true;",
    ],
    "excludedFromDividends": lambda p: [
        f"        return _excludedFromDividends[{_p(p,0,'account')}];",
    ],
    "lastClaimTimes": lambda p: [
        f"        return _lastClaimTimes[{_p(p,0,'account')}];",
    ],
    "claimWait": lambda p: [
        "        return _claimWait;",
    ],
    "updateClaimWait": lambda p: [
        f"        require({_p(p,0,'newClaimWait')} >= 3600 && {_p(p,0,'newClaimWait')} <= 86400);",
        f"        emit ClaimWaitUpdated({_p(p,0,'newClaimWait')}, _claimWait);",
        f"        _claimWait = {_p(p,0,'newClaimWait')};",
    ],
    "getNumberOfTokenHolders": lambda p: [
        "        return _getNumberOfTokenHolders.length;",
    ],
    "lastProcessedIndex": lambda p: [
        "        return _lastProcessedIndex;",
    ],
    "getLastProcessedIndex": lambda p: [
        "        return _lastProcessedIndex;",
    ],
    "totalDividendsDistributed": lambda p: [
        "        return _totalDividendsDistributed;",
    ],
    "minimumTokenBalanceForDividends": lambda p: [
        "        return 0x2a5a058fc295ed000000;  // 500 * 10**18",
    ],
    "setBalance": lambda p: [
        f"        require(msg.sender == _owner, 'Ownable: caller is not the owner');",
        f"        if (!_excludedFromDividends[{p[0] if p else 'account'}]) {{",
        f"            if ({p[1] if len(p)>1 else 'newBalance'} < minimumTokenBalanceForDividends()) {{",
        f"                _setBalance({p[0] if p else 'account'}, 0);",
        f"            }} else {{",
        f"                _setBalance({p[0] if p else 'account'}, {p[1] if len(p)>1 else 'newBalance'});",
        f"            }}",
        f"            _processAccount({p[0] if p else 'account'}, true);",
        f"        }}",
    ],
    "getAccount": lambda p: [
        f"        (uint256 _dividends, uint256 _lastProcessedIndex_, uint256 _nextClaimTime,",
        f"         uint256 _secondsUntilAutoClaim, uint256 _totalSupply_,",
        f"         uint256 _balance, uint256 _withdrawableDivs) = _getAccount({p[0] if p else 'account'});",
    ],
    "getAccountAtIndex": lambda p: [
        f"        require({p[0] if p else 'index'} < _getNumberOfTokenHolders.length, 'index out of bounds');",
        f"        address account = _getNumberOfTokenHolders[{p[0] if p else 'index'}];",
        f"        return getAccount(account);",
    ],
    "processAccount": lambda p: [
        f"        return _processAccount({p[0] if p else 'account'}, {p[1] if len(p)>1 else 'automatic'});",
    ],
    "process": lambda p: [
        f"        if (_getNumberOfTokenHolders.length > 0) {{",
        f"            uint256 _currentIndex = _lastProcessedIndex;",
        f"            uint256 _iterations = 0;",
        f"            while (_iterations < {p[0] if p else 'gas'} && _currentIndex < _getNumberOfTokenHolders.length) {{",
        f"                _currentIndex++;",
        f"                if (_currentIndex >= _getNumberOfTokenHolders.length) _currentIndex = 0;",
        f"                if (_shouldDistribute(_getNumberOfTokenHolders[_currentIndex])) {{",
        f"                    _processAccount(_getNumberOfTokenHolders[_currentIndex], true);",
        f"                    _iterations++;",
        f"                }}",
        f"                _iterations++;",
        f"            }}",
        f"            _lastProcessedIndex = _currentIndex;",
        f"        }}",
    ],
    "distributeDOGEDividends": lambda p: [
        f"        // distribute {_p(p,0,'amount')} DOGE dividends",
        "        revert();",
    ],
    "DOGE": lambda p: [
        "        return address(0xe09fabb73bd3ade0a17ecc321fd13a19e81ce82);",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Chainlink / Oracle
# ─────────────────────────────────────────────────────────────────────────────
ORACLE_STUBS = {
    "latestRoundData": lambda p: [
        "        return (_roundId, _answer, _startedAt, _updatedAt, _answeredInRound);",
    ],
    "getRoundData": lambda p: [
        f"        return (_roundId, _answer, _startedAt, _updatedAt, _answeredInRound);",
    ],
    "latestAnswer": lambda p: [
        "        return _answer;",
    ],
    "latestRound": lambda p: [
        "        return _roundId;",
    ],
    "decimals": lambda p: [
        "        return _decimals;",
    ],
    "description": lambda p: [
        "        return _description;",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Multicall
# ─────────────────────────────────────────────────────────────────────────────
MULTICALL_STUBS = {
    "multicall": lambda p: [
        f"        // multicall: batch {_p(p,0,'data').length} calls",
        "        revert();",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Diamond (EIP-2535)
# ─────────────────────────────────────────────────────────────────────────────
DIAMOND_STUBS = {
    "diamondCut": lambda p: [
        "        // Diamond proxy cut",
        "        revert();",
    ],
    "facetAddress": lambda p: [
        f"        return _facets[{_p(p,0,'functionSelector')}];",
    ],
    "facetAddresses": lambda p: [
        "        return _facetAddresses;",
    ],
    "facetFunctionSelectors": lambda p: [
        f"        return _facetFunctionSelectors[{_p(p,0,'facet')}];",
    ],
    "facets": lambda p: [
        "        return _facets;",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Gnosis Safe
# ─────────────────────────────────────────────────────────────────────────────
GNOSIS_SAFE_STUBS = {
    "execTransaction": lambda p: [
        "        // Gnosis Safe execTransaction",
        "        revert();",
    ],
    "nonce": lambda p: [
        "        return _nonce;",
    ],
    "getOwners": lambda p: [
        "        return _owners;",
    ],
    "getThreshold": lambda p: [
        "        return _threshold;",
    ],
    "isOwner": lambda p: [
        f"        return _isOwner[{_p(p,0,'account')}];",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Proxy / UUPS / Beacon
# ─────────────────────────────────────────────────────────────────────────────
PROXY_STUBS = {
    "implementation": lambda p: [
        "        return _implementation;",
    ],
    "upgradeTo": lambda p: [
        f"        _upgradeTo({_p(p,0,'newImplementation')});",
    ],
    "upgradeToAndCall": lambda p: [
        f"        _upgradeToAndCall({_p(p,0,'newImplementation')}, {_p(p,1,'data')});",
    ],
    "proxiableUUID": lambda p: [
        "        return bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1);",
    ],
    "beacon": lambda p: [
        "        return _beacon;",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Staking
# ─────────────────────────────────────────────────────────────────────────────
STAKING_STUBS = {
    "stake": lambda p: [
        f"        _stake({_p(p,0,'amount')});",
    ],
    "unstake": lambda p: [
        f"        _unstake({_p(p,0,'amount')});",
    ],
    "earned": lambda p: [
        f"        return _earned({_p(p,0,'account')});",
    ],
    "rewardPerToken": lambda p: [
        "        return _rewardPerToken();",
    ],
    "stakingToken": lambda p: [
        "        return _stakingToken;",
    ],
    "rewardsToken": lambda p: [
        "        return _rewardsToken;",
    ],
    "rewardRate": lambda p: [
        "        return _rewardRate;",
    ],
    "totalStaked": lambda p: [
        "        return _totalStaked;",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Vesting
# ─────────────────────────────────────────────────────────────────────────────
VESTING_STUBS = {
    "vestedAmount": lambda p: [
        f"        return _vestedAmount({_p(p,0,'beneficiary')});",
    ],
    "releasable": lambda p: [
        f"        return _releasable({_p(p,0,'beneficiary')});",
    ],
    "release": lambda p: [
        f"        _release({_p(p,0,'beneficiary')});",
    ],
    "createVestingSchedule": lambda p: [
        "        revert();",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Timelock
# ─────────────────────────────────────────────────────────────────────────────
TIMELOCK_STUBS = {
    "delay": lambda p: [
        "        return _delay;",
    ],
    "pendingAdmin": lambda p: [
        "        return _pendingAdmin;",
    ],
    "queuedTransactions": lambda p: [
        f"        return _queuedTransactions[keccak256(abi.encode({_p(p,0,'target')}, {_p(p,1,'value')}, {_p(p,2,'signature')}, {_p(p,3,'data')}, {_p(p,4,'eta')}))];",
    ],
    "queueTransaction": lambda p: [
        "        revert();",
    ],
    "executeTransaction": lambda p: [
        "        revert();",
    ],
    "cancelTransaction": lambda p: [
        "        revert();",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  MERGE ALL INTO MASTER DICT
# ─────────────────────────────────────────────────────────────────────────────
KNOWN_STUBS = {}
for category in [
    ERC721_STUBS,
    ERC1155_STUBS,
    ERC4626_STUBS,
    OWNABLE_STUBS,
    PAUSABLE_STUBS,
    ACCESS_CONTROL_STUBS,
    UNISWAP_V2_STUBS,
    UNISWAP_V3_STUBS,
    FLASH_LOAN_STUBS,
    DIVIDEND_STUBS,
    ORACLE_STUBS,
    MULTICALL_STUBS,
    DIAMOND_STUBS,
    GNOSIS_SAFE_STUBS,
    PROXY_STUBS,
    STAKING_STUBS,
    VESTING_STUBS,
    TIMELOCK_STUBS,
    ERC20_STUBS,          # ERC-20 LAST — overrides balanceOf etc from ERC-1155
]:
    KNOWN_STUBS.update(category)

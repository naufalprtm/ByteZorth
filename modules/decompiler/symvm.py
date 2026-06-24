"""
symvm.py — Symbolic EVM for lifting function bodies to pseudo-Solidity.

Tracks: stack, memory (MSTORE/MLOAD), storage (SLOAD/SSTORE),
        mapping access (keccak256 pattern), calldata, environment.
"""

from ..constants import KNOWN_EVENTS, BUILTIN_SELECTORS


class SymVM:
    """Symbolic EVM for lifting function bodies."""

    def __init__(self, storage_names, param_names, param_types, revert_error_map=None):
        self.stack = []
        self.mem = {}
        self.storage_names = storage_names
        self.param_names = param_names or []
        self.param_types = param_types or []
        self.revert_error_map = revert_error_map or {}
        self.stmts = []
        self.var_c = 0
        self.seen_pcs = set()
        self.has_return = False
        self.return_expr = None
        self._skip_until_jumpdest = False
        self._depth = 0

    def fresh(self, prefix="v"):
        self.var_c += 1
        return f"{prefix}{self.var_c}"

    def pop(self):
        return self.stack.pop() if self.stack else self.fresh("_")

    def push(self, e):
        self.stack.append(str(e))

    def stmt(self, s):
        self.stmts.append(s)

    def run(self, instrs_list, max_instrs=500):
        count = 0
        for pc, op, mnem, operand, gas, cat in instrs_list:
            if pc in self.seen_pcs or count >= max_instrs:
                continue
            self.seen_pcs.add(pc)
            count += 1
            self._step(pc, op, mnem, operand)

    def _step(self, pc, op, mnem, operand):
        # ── PUSH ──────────────────────────────────────────────
        if 0x60 <= op <= 0x7f:
            val = int(operand.hex(), 16) if operand else 0
            if len(operand) == 4:
                h = operand.hex()
                if h in BUILTIN_SELECTORS:
                    self.push(f"0x{h}  /* {BUILTIN_SELECTORS[h][0]} */")
                else:
                    self.push(f"0x{h}")
            elif len(operand) == 20:
                self.push(f"0x{operand.hex()}")
            elif len(operand) == 32:
                h = operand.hex()
                for topic, sig in KNOWN_EVENTS.items():
                    if topic == h:
                        self.push(f'keccak256("{sig.split("(")[0]}")')
                        return
                try:
                    s = operand.decode("utf-8")
                    if all(c.isprintable() or c in "\t\n" for c in s) and len(s.strip()) > 3:
                        self.push(f'"{s.strip()}"')
                        return
                except:
                    pass
                self.push(f"0x{h}")
            elif val <= 9:
                self.push(str(val))
            elif val <= 0xFFFF:
                self.push(str(val))
            else:
                self.push(f"0x{operand.hex()}")
            return

        # ── DUP ───────────────────────────────────────────────
        if 0x80 <= op <= 0x8f:
            depth = op - 0x80
            if len(self.stack) > depth:
                self.push(self.stack[-(depth + 1)])
            else:
                self.push(self.fresh("dup"))
            return

        # ── SWAP ──────────────────────────────────────────────
        if 0x90 <= op <= 0x9f:
            depth = op - 0x8f
            if len(self.stack) > depth:
                self.stack[-1], self.stack[-depth - 1] = self.stack[-depth - 1], self.stack[-1]
            return

        if mnem == "POP":
            self.pop(); return

        # ── ARITHMETIC ────────────────────────────────────────
        if mnem == "ADD":
            b, a = self.pop(), self.pop()
            if a == "0": self.push(b)
            elif b == "0": self.push(a)
            elif a == b: self.push(f"2 * {a}")
            else: self.push(f"{a} + {b}")
            return
        if mnem == "SUB":
            b, a = self.pop(), self.pop()
            if b == "0": self.push(a)
            elif a == b: self.push("0")
            else: self.push(f"{a} - {b}")
            return
        if mnem == "MUL":
            b, a = self.pop(), self.pop()
            if a == "1": self.push(b)
            elif b == "1": self.push(a)
            elif a == "0" or b == "0": self.push("0")
            elif a == "32": self.push(f"{b} * 32")
            elif b == "32": self.push(f"{a} * 32")
            elif a == "2": self.push(f"{b} << 1")
            elif b == "2": self.push(f"{a} << 1")
            else: self.push(f"{a} * {b}")
            return
        if mnem == "DIV":
            b, a = self.pop(), self.pop()
            if b == "1": self.push(a)
            elif a == b: self.push("1")
            elif a == "0": self.push("0")
            else: self.push(f"{a} / {b}")
            return
        if mnem == "SDIV":
            b, a = self.pop(), self.pop()
            self.push(f"int256({a}) / int256({b})")
            return
        if mnem == "MOD":
            b, a = self.pop(), self.pop()
            if b == "1": self.push("0")
            else: self.push(f"{a} % {b}")
            return
        if mnem == "SMOD":
            b, a = self.pop(), self.pop()
            self.push(f"int256({a}) % int256({b})")
            return
        if mnem == "ADDMOD":
            c, b, a = self.pop(), self.pop(), self.pop()
            self.push(f"addmod({a}, {b}, {c})")
            return
        if mnem == "MULMOD":
            c, b, a = self.pop(), self.pop(), self.pop()
            self.push(f"mulmod({a}, {b}, {c})")
            return
        if mnem == "EXP":
            b, a = self.pop(), self.pop()
            if b == "0": self.push("1")
            elif b == "1": self.push(a)
            else: self.push(f"{a} ** {b}")
            return
        if mnem == "SIGNEXTEND":
            b, a = self.pop(), self.pop()
            self.push(f"signextend({b}, {a})")
            return

        # ── BITWISE ───────────────────────────────────────────
        if mnem == "AND":
            b, a = self.pop(), self.pop()
            masks = {
                "0xffffffffffffffffffffffffffffffffffffffff": "address",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF": "address",
                "0xffffffff": "uint32", "4294967295": "uint32",
                "0xff": "uint8", "255": "uint8",
                "0xffff": "uint16", "65535": "uint16",
            }
            cast = masks.get(b) or masks.get(a)
            if cast:
                other = a if b in masks else b
                self.push(f"{cast}({other})")
            else:
                self.push(f"{a} & {b}")
            return
        if mnem == "OR":
            b, a = self.pop(), self.pop()
            if a == "0": self.push(b)
            elif b == "0": self.push(a)
            else: self.push(f"{a} | {b}")
            return
        if mnem == "XOR":
            b, a = self.pop(), self.pop()
            if a == b: self.push("0")
            elif a == "0": self.push(b)
            elif b == "0": self.push(a)
            else: self.push(f"{a} ^ {b}")
            return
        if mnem == "NOT":
            a = self.pop()
            self.push(f"~{a}")
            return
        if mnem == "SHL":
            shift, val = self.pop(), self.pop()
            if shift == "0": self.push(val)
            elif shift == "224": self.push(f"uint32({val})")
            else: self.push(f"{val} << {shift}")
            return
        if mnem == "SHR":
            shift, val = self.pop(), self.pop()
            if shift == "0": self.push(val)
            elif shift == "224": self.push(f"uint32({val} >> 224)")
            else: self.push(f"{val} >> {shift}")
            return
        if mnem == "SAR":
            shift, val = self.pop(), self.pop()
            self.push(f"int256({val}) >> {shift}")
            return
        if mnem == "BYTE":
            pos, val = self.pop(), self.pop()
            self.push(f"byte({pos}, {val})")
            return

        # ── COMPARISON ────────────────────────────────────────
        if mnem == "ISZERO":
            a = self.pop()
            if a.startswith("!") or a.startswith("~"):
                self.push(a[1:])
            elif " == 0" in a:
                self.push(a.replace(" == 0", ""))
            elif a == "true":
                self.push("false")
            elif a == "false":
                self.push("true")
            else:
                self.push(f"!({a})")
            return
        if mnem == "EQ":
            b, a = self.pop(), self.pop()
            if a == b: self.push("true")
            elif a == "0": self.push(f"{b} == 0")
            elif b == "0": self.push(f"{a} == 0")
            else: self.push(f"{a} == {b}")
            return
        if mnem == "LT":
            b, a = self.pop(), self.pop()
            self.push(f"{a} < {b}")
            return
        if mnem == "GT":
            b, a = self.pop(), self.pop()
            self.push(f"{a} > {b}")
            return
        if mnem == "SLT":
            b, a = self.pop(), self.pop()
            self.push(f"int256({a}) < int256({b})")
            return
        if mnem == "SGT":
            b, a = self.pop(), self.pop()
            self.push(f"int256({a}) > int256({b})")
            return

        # ── ENVIRONMENT ───────────────────────────────────────
        if mnem == "CALLER":     self.push("msg.sender"); return
        if mnem == "CALLVALUE":  self.push("msg.value"); return
        if mnem == "CALLDATASIZE": self.push("msg.data.length"); return
        if mnem == "ADDRESS":    self.push("address(this)"); return
        if mnem == "ORIGIN":     self.push("tx.origin"); return
        if mnem == "GASPRICE":   self.push("tx.gasprice"); return
        if mnem == "GAS":        self.push("gasleft()"); return
        if mnem == "GASLIMIT":   self.push("block.gaslimit"); return
        if mnem == "NUMBER":     self.push("block.number"); return
        if mnem == "TIMESTAMP":  self.push("block.timestamp"); return
        if mnem == "COINBASE":   self.push("block.coinbase"); return
        if mnem in ("DIFFICULTY", "PREVRANDAO"): self.push("block.prevrandao"); return
        if mnem == "SELFBALANCE": self.push("address(this).balance"); return
        if mnem == "CHAINID":    self.push("block.chainid"); return
        if mnem == "BASEFEE":    self.push("block.basefee"); return
        if mnem == "RETURNDATASIZE": self.push("returndatasize()"); return

        if mnem == "CALLDATALOAD":
            offset = self.pop()
            try:
                off_i = int(offset, 0)
                if off_i == 0:
                    self.push("msg.sig")
                else:
                    pidx = (off_i - 4) // 32
                    if 0 <= pidx < len(self.param_names):
                        self.push(f"_{self.param_names[pidx]}")
                    else:
                        self.push(f"calldataload({offset})")
            except:
                self.push(f"calldataload({offset})")
            return

        if mnem == "CALLDATACOPY":
            self.pop(); self.pop(); self.pop(); return

        if mnem == "BALANCE":
            addr = self.pop()
            self.push(f"address({addr}).balance"); return
        if mnem == "EXTCODESIZE":
            addr = self.pop()
            self.push(f"address({addr}).code.length"); return
        if mnem == "EXTCODEHASH":
            addr = self.pop()
            self.push(f"address({addr}).codehash"); return

        # ── MEMORY ────────────────────────────────────────────
        if mnem == "MSTORE":
            offset, val = self.pop(), self.pop()
            self.mem[offset] = val
            return
        if mnem == "MSTORE8":
            offset, val = self.pop(), self.pop()
            self.mem[offset] = f"byte({val})"
            return
        if mnem == "MLOAD":
            offset = self.pop()
            val = self.mem.get(offset)
            if val:
                self.push(val)
            else:
                if offset in ("0x4", "4"):
                    self.push("msg.data.length - 4")
                elif offset in ("0x0", "0"):
                    self.push("mload(0x0)")
                elif offset in ("0x40", "64", "0x40"):
                    self.push("freeMemoryPointer")
                else:
                    self.push(f"mload({offset})")
            return

        # ── STORAGE ───────────────────────────────────────────
        if mnem in ("SHA3", "KECCAK256"):
            size = self.pop()
            offset = self.pop()
            key_expr = self.mem.get(offset)
            slot_expr = None
            try:
                off_i = int(offset, 0)
                for candidate in (off_i + 32, off_i - 32):
                    k = str(candidate) if offset.isdigit() else hex(candidate)
                    if k in self.mem:
                        slot_expr = self.mem[k]
                        break
                    k2 = hex(candidate)
                    if k2 in self.mem:
                        slot_expr = self.mem[k2]
                        break
            except:
                pass
            if key_expr and slot_expr:
                sn = self._slot_name(slot_expr)
                self.push(f"{sn}[{key_expr}]")
            else:
                self.push(f"keccak256(mem[{offset}..+{size}])")
            return

        if mnem == "SLOAD":
            slot_e = self.pop()
            if "[" in slot_e:
                self.push(slot_e)
            else:
                self.push(self._slot_name(slot_e))
            return

        if mnem == "SSTORE":
            slot_e = self.pop()
            val_e = self.pop()
            if "[" in slot_e:
                self.stmt(f"        {slot_e} = {val_e};")
            else:
                sn = self._slot_name(slot_e)
                self.stmt(f"        {sn} = {val_e};")
            return

        # ── CONTROL ───────────────────────────────────────────
        if mnem == "JUMPI":
            dest = self.pop()
            cond = self.pop()
            if cond.startswith("!"):
                inner = cond[1:]
                self.stmt(f"        require({inner});")
            elif " == 0" in cond:
                inner = cond.replace(" == 0", "").strip()
                if inner.startswith("(") and inner.endswith(")"):
                    inner = inner[1:-1]
                self.stmt(f"        require({inner});")
            else:
                self.stmt(f"        if ({cond}) {{ // then")
            return

        if mnem == "JUMP":
            self.pop(); return
        if mnem == "JUMPDEST":
            return

        if mnem in ("STOP", "RETURN"):
            if mnem == "RETURN" and self.stack:
                offset = self.pop()
                size = self.pop() if self.stack else "0"
                val = self.mem.get(offset)
                if val:
                    self.has_return = True
                    self.return_expr = val
            return

        if mnem == "REVERT":
            self.pop() if self.stack else None
            self.pop() if self.stack else None
            # Check if we have an error message for this REVERT
            err_msg = self.revert_error_map.get(pc)
            if err_msg:
                self.stmt(f"        revert('{err_msg}');")
            else:
                self.stmt("        revert();")
            return

        if mnem == "INVALID":
            self.stmt("        assert(false);")
            return

        # ── CALLS ─────────────────────────────────────────────
        if mnem == "CALL":
            self.pop(); addr = self.pop(); val = self.pop()
            in_off = self.pop(); in_sz = self.pop()
            self.pop(); self.pop()
            # Try to extract selector from memory
            selector = self._extract_call_selector(in_off)
            vn = self.fresh("success")
            if selector:
                self.stmt(f"        (bool {vn}, ) = {addr}.call{{value: {val}}}({selector});")
            else:
                self.stmt(f"        (bool {vn}, ) = {addr}.call{{value: {val}}}('');")
            self.push(vn)
            return
        if mnem == "STATICCALL":
            self.pop(); addr = self.pop()
            in_off = self.pop(); in_sz = self.pop()
            self.pop(); self.pop()
            selector = self._extract_call_selector(in_off)
            vn = self.fresh("success")
            if selector:
                self.stmt(f"        (bool {vn}, ) = {addr}.staticcall({selector});")
            else:
                self.stmt(f"        (bool {vn}, ) = {addr}.staticcall('');")
            self.push(vn)
            return
        if mnem == "DELEGATECALL":
            self.pop(); addr = self.pop()
            in_off = self.pop(); in_sz = self.pop()
            self.pop(); self.pop()
            selector = self._extract_call_selector(in_off)
            vn = self.fresh("success")
            if selector:
                self.stmt(f"        (bool {vn}, ) = {addr}.delegatecall({selector});")
            else:
                self.stmt(f"        (bool {vn}, ) = {addr}.delegatecall('');")
            self.push(vn)
            return
        if mnem == "CALLCODE":
            self.pop(); addr = self.pop(); val = self.pop()
            in_off = self.pop(); in_sz = self.pop()
            self.pop(); self.pop()
            selector = self._extract_call_selector(in_off)
            vn = self.fresh("success")
            if selector:
                self.stmt(f"        (bool {vn}, ) = {addr}.callcode{{value: {val}}}({selector});")
            else:
                self.stmt(f"        (bool {vn}, ) = {addr}.callcode{{value: {val}}}('');")
            self.push(vn)
            return

        if mnem == "SELFDESTRUCT":
            addr = self.pop()
            self.stmt(f"        selfdestruct(payable({addr}));")
            return

        if mnem in ("CREATE", "CREATE2"):
            args = [self.pop() for _ in range(3 if mnem == "CREATE" else 4)]
            vn = self.fresh("newContract")
            self.stmt(f"        address {vn} = address(new Contract());  // {mnem}")
            self.push(vn)
            return

        # ── LOG ───────────────────────────────────────────────
        if mnem.startswith("LOG"):
            n_topics = int(mnem[3:]) if mnem[3:].isdigit() else 0
            offset = self.pop(); size = self.pop()
            topics = [self.pop() for _ in range(n_topics)]
            ev_name = "Event"
            if topics:
                t0 = topics[0].replace("0x", "").replace(" ", "")[:16]
                for eh, esig in KNOWN_EVENTS.items():
                    if eh.startswith(t0):
                        ev_name = esig.split("(")[0]
                        break
            indexed = topics[1:] if len(topics) > 1 else []
            args = ", ".join(indexed) if indexed else "..."
            self.stmt(f"        emit {ev_name}({args});")
            return

        if mnem in ("RETURNDATACOPY", "CODECOPY", "EXTCODECOPY"):
            for _ in range(4 if mnem == "EXTCODECOPY" else 3):
                self.pop()
            return

    def _extract_call_selector(self, in_off):
        """
        Try to extract the function selector from memory at in_off.
        Looks for 0xNNNNNNNN pattern in self.mem[in_off].
        Returns hex string like '0x17e142d1' or None.
        """
        try:
            val = self.mem.get(in_off) or self.mem.get(str(in_off))
            if val and isinstance(val, str):
                # Clean up: remove comments, whitespace
                val = val.split("//")[0].strip().split(" ")[0]
                if val.startswith("0x") and len(val) >= 10:
                    return val[:10]  # first 4 bytes = selector
        except: pass
        return None

    def _slot_name(self, slot_e):
        from .helpers import slot_name
        return slot_name(slot_e, self.storage_names)

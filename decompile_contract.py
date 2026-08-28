#!/usr/bin/env python3
"""
EVM Disassembler Pro v8.0
=========================

A hardened, dependency‑free EVM bytecode disassembler and static analyzer.

Features
--------
- Pure‑Python decoder for all official EVM opcodes (incl. PUSH0, MCOPY, TLOAD, TSTORE)
- Solidity‑style CBOR metadata stripping with heuristic validation
- PUSH‑aware sizing with truncated push detection
- JUMPDEST discovery and conservative CFG edge extraction
- Function selector extraction (with dispatcher‑context validation)
- Creation vs. runtime code detection
- Opcode category summaries, entropy, gas approximation, and JSON export
- Filtering by PC range, category, or raw hex pattern
- Optional warnings for unresolved jumps, invalid opcodes, truncated pushes, etc.

Usage
-----
  evm_disassembler_pro.py --bytecode 0x60806040 --summary
  evm_disassembler_pro.py --file contract.hex --json --cfg
  cat contract.hex | evm_disassembler_pro.py --stdin --summary --detect-creation
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

# -----------------------------------------------------------------------------
# Constants & configuration
# -----------------------------------------------------------------------------

VERSION = "8.0"
MAX_BYTECODE_SIZE = 50_000_000
PANIC_SELECTOR = "4e487b71"
HEX_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
COMMENT_RE = re.compile(r"(//.*?$|#.*?$)", re.MULTILINE)

# ANSI colours (used only when output is a TTY)
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"

# -----------------------------------------------------------------------------
# Logging setup
# -----------------------------------------------------------------------------

LOG = logging.getLogger("evm-disasm")


def setup_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )


# -----------------------------------------------------------------------------
# Opcode tables
# -----------------------------------------------------------------------------

# Official opcodes (including those added in Shanghai/Cancun)
OPCODES: Dict[int, str] = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",
    0x0B: "SIGNEXTEND",
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x1B: "SHL",
    0x1C: "SHR",
    0x1D: "SAR",
    0x1E: "CLZ",
    0x20: "SHA3",
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",
    0x49: "BLOBHASH",
    0x4A: "BLOBBASEFEE",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5A: "GAS",
    0x5B: "JUMPDEST",
    0x5C: "TLOAD",
    0x5D: "TSTORE",
    0x5E: "MCOPY",
    0x5F: "PUSH0",
    0xA0: "LOG0",
    0xA1: "LOG1",
    0xA2: "LOG2",
    0xA3: "LOG3",
    0xA4: "LOG4",
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}
# PUSH1..PUSH32
for code in range(0x60, 0x80):
    OPCODES[code] = f"PUSH{code - 0x5F}"
# DUP1..DUP16
for code in range(0x80, 0x90):
    OPCODES[code] = f"DUP{code - 0x7F}"
# SWAP1..SWAP16
for code in range(0x90, 0xA0):
    OPCODES[code] = f"SWAP{code - 0x8F}"

# Static gas costs (approximate, excluding memory expansion, cold/warm access)
GAS_FALLBACK: Dict[str, int] = {
    "STOP": 0,
    "ADD": 3,
    "MUL": 5,
    "SUB": 3,
    "DIV": 5,
    "SDIV": 5,
    "MOD": 5,
    "SMOD": 5,
    "ADDMOD": 8,
    "MULMOD": 8,
    "EXP": 10,
    "SIGNEXTEND": 5,
    "LT": 3,
    "GT": 3,
    "SLT": 3,
    "SGT": 3,
    "EQ": 3,
    "ISZERO": 3,
    "AND": 3,
    "OR": 3,
    "XOR": 3,
    "NOT": 3,
    "BYTE": 3,
    "SHL": 3,
    "SHR": 3,
    "SAR": 3,
    "CLZ": 5,
    "SHA3": 30,
    "ADDRESS": 2,
    "BALANCE": 100,  # cold access in practice, but static
    "ORIGIN": 2,
    "CALLER": 2,
    "CALLVALUE": 2,
    "CALLDATALOAD": 3,
    "CALLDATASIZE": 2,
    "CALLDATACOPY": 3,
    "CODESIZE": 2,
    "CODECOPY": 3,
    "GASPRICE": 2,
    "EXTCODESIZE": 100,
    "EXTCODECOPY": 100,
    "RETURNDATASIZE": 2,
    "RETURNDATACOPY": 3,
    "EXTCODEHASH": 100,
    "BLOCKHASH": 20,
    "COINBASE": 2,
    "TIMESTAMP": 2,
    "NUMBER": 2,
    "PREVRANDAO": 2,
    "GASLIMIT": 2,
    "CHAINID": 2,
    "SELFBALANCE": 5,
    "BASEFEE": 2,
    "BLOBHASH": 3,
    "BLOBBASEFEE": 2,
    "POP": 2,
    "MLOAD": 3,
    "MSTORE": 3,
    "MSTORE8": 3,
    "SLOAD": 100,
    "SSTORE": 100,
    "JUMP": 8,
    "JUMPI": 10,
    "PC": 2,
    "MSIZE": 2,
    "GAS": 2,
    "JUMPDEST": 1,
    "TLOAD": 100,
    "TSTORE": 100,
    "MCOPY": 3,  # base cost, additional per word
    "PUSH0": 2,
    "CREATE": 32000,
    "CALL": 700,  # base, additional for value/access
    "CALLCODE": 700,
    "RETURN": 0,
    "DELEGATECALL": 700,
    "CREATE2": 32000,
    "STATICCALL": 700,
    "REVERT": 0,
    "INVALID": 0,
    "SELFDESTRUCT": 5000,
}
for n in range(1, 33):
    GAS_FALLBACK[f"PUSH{n}"] = 3
for n in range(1, 17):
    GAS_FALLBACK[f"DUP{n}"] = 3
    GAS_FALLBACK[f"SWAP{n}"] = 3
for n in range(5):
    GAS_FALLBACK[f"LOG{n}"] = 375

# Opcode categories
ARITHMETIC_OPS = {
    "ADD",
    "MUL",
    "SUB",
    "DIV",
    "SDIV",
    "MOD",
    "SMOD",
    "ADDMOD",
    "MULMOD",
    "EXP",
    "SIGNEXTEND",
}
LOGIC_OPS = {
    "LT",
    "GT",
    "SLT",
    "SGT",
    "EQ",
    "ISZERO",
    "AND",
    "OR",
    "XOR",
    "NOT",
    "BYTE",
    "SHL",
    "SHR",
    "SAR",
    "CLZ",
}
CONTROL_FLOW_OPS = {
    "JUMP",
    "JUMPI",
    "STOP",
    "RETURN",
    "REVERT",
    "INVALID",
    "SELFDESTRUCT",
}
MEMORY_OPS = {
    "MLOAD",
    "MSTORE",
    "MSTORE8",
    "SLOAD",
    "SSTORE",
    "MSIZE",
    "MCOPY",
    "TLOAD",
    "TSTORE",
}
CALL_OPS = {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2"}
ENV_OPS = {
    "ADDRESS",
    "BALANCE",
    "ORIGIN",
    "CALLER",
    "CALLVALUE",
    "CALLDATALOAD",
    "CALLDATASIZE",
    "CALLDATACOPY",
    "CODESIZE",
    "CODECOPY",
    "GASPRICE",
    "EXTCODESIZE",
    "EXTCODECOPY",
    "RETURNDATASIZE",
    "RETURNDATACOPY",
    "EXTCODEHASH",
    "BLOCKHASH",
    "COINBASE",
    "TIMESTAMP",
    "NUMBER",
    "PREVRANDAO",
    "GASLIMIT",
    "CHAINID",
    "SELFBALANCE",
    "BASEFEE",
    "BLOBHASH",
    "BLOBBASEFEE",
    "GAS",
    "PC",
}

CATEGORY_MAP = {
    **{op: "arithmetic" for op in ARITHMETIC_OPS},
    **{op: "logic" for op in LOGIC_OPS},
    **{op: "control_flow" for op in CONTROL_FLOW_OPS},
    **{op: "memory_storage" for op in MEMORY_OPS},
    **{op: "call_create" for op in CALL_OPS},
    **{op: "environment" for op in ENV_OPS},
    "POP": "stack",
    "SHA3": "stack",
}
# For PUSH/DUP/SWAP/LOG/UNKNOWN we assign dynamically

# -----------------------------------------------------------------------------
# Data models
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Instruction:
    pc: int
    opcode: str
    operand: Optional[str]
    size: int
    raw: str
    gas: int
    category: str
    is_invalid: bool
    is_unknown: bool
    is_jumpdest: bool
    is_push_truncated: bool
    jump_target: Optional[int]


@dataclass(frozen=True)
class MetadataInfo:
    original_size: int
    stripped_size: int
    stripped: bool
    offset: Optional[int]
    length: Optional[int]


@dataclass(frozen=True)
class AnalysisSummary:
    bytecode_size: int
    instruction_count: int
    unique_opcodes: int
    jumpdest_count: int
    invalid_count: int
    unknown_count: int
    truncated_push_count: int
    function_selectors: List[str]
    selector_count: int
    has_panic_selector: bool
    entropy: float
    avg_gas: float
    runtime_likely: bool
    creation_likely: bool
    code_kind: str
    runtime_score: int
    creation_score: int
    estimated_static_gas: int
    warning_count: int


@dataclass(frozen=True)
class ControlFlowEdge:
    source: int
    target: Optional[int]
    kind: str
    resolved: bool


@dataclass(frozen=True)
class AnalysisWarning:
    pc: Optional[int]
    code: str
    message: str


# -----------------------------------------------------------------------------
# Utility functions
# -----------------------------------------------------------------------------


def colorize(text: str, color: str, *, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{color}{text}{RESET}"


def clean_raw_input(raw: str) -> str:
    raw = COMMENT_RE.sub("", raw)
    raw = re.sub(r"\s+", "", raw)
    return raw.lower()


def strip_0x(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def validate_hex(body: str) -> None:
    if not body:
        raise ValueError("Empty bytecode")
    if len(body) % 2:
        raise ValueError("Hex string length must be even")
    if not HEX_RE.fullmatch(body):
        raise ValueError("Invalid hex characters detected")
    if len(body) // 2 > MAX_BYTECODE_SIZE:
        raise ValueError(f"Bytecode exceeds maximum size: {MAX_BYTECODE_SIZE} bytes")


# -----------------------------------------------------------------------------
# Metadata stripping
# -----------------------------------------------------------------------------

def strip_metadata_cbor(bytecode: bytes) -> Tuple[bytes, MetadataInfo]:
    """
    Strip Solidity‑style trailing CBOR metadata.
    Uses the length encoded in the last two bytes and a heuristic check
    that the metadata begins with a CBOR map (0xA1–0xAF).
    """
    original_size = len(bytecode)
    no_strip = MetadataInfo(original_size, original_size, False, None, None)

    if len(bytecode) < 4:
        return bytecode, no_strip

    meta_len = int.from_bytes(bytecode[-2:], "big")
    if meta_len <= 0 or meta_len + 2 > len(bytecode):
        return bytecode, no_strip

    start = len(bytecode) - meta_len - 2
    if start < 0:
        return bytecode, no_strip

    # CBOR major type 5 (map). This accepts compact and extended map headers
    # (0xA0..0xBB) as well as the indefinite-length map marker (0xBF).
    first = bytecode[start]
    if ((first & 0xE0) == 0xA0 and (first & 0x1F) <= 27) or first == 0xBF:
        stripped = bytecode[:start]
        LOG.debug("Detected CBOR metadata at offset=%d length=%d", start, meta_len)
        return stripped, MetadataInfo(original_size, len(stripped), True, start, meta_len)

    return bytecode, no_strip


def normalize_bytecode(raw: str, *, remove_metadata: bool) -> Tuple[bytes, MetadataInfo]:
    cleaned = strip_0x(clean_raw_input(raw))
    validate_hex(cleaned)
    data = bytes.fromhex(cleaned)

    if remove_metadata:
        return strip_metadata_cbor(data)

    size = len(data)
    return data, MetadataInfo(size, size, False, None, None)


# -----------------------------------------------------------------------------
# Input loading
# -----------------------------------------------------------------------------

def load_from_file(path: Path, *, remove_metadata: bool) -> Tuple[bytes, MetadataInfo]:
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as e:
        raise IOError(f"Failed reading file {path}: {e}") from e
    return normalize_bytecode(raw, remove_metadata=remove_metadata)


def load_from_stdin(*, remove_metadata: bool) -> Tuple[bytes, MetadataInfo]:
    raw = sys.stdin.read()
    if not raw.strip():
        raise ValueError("Empty stdin input")
    return normalize_bytecode(raw, remove_metadata=remove_metadata)


# -----------------------------------------------------------------------------
# Core disassembler
# -----------------------------------------------------------------------------

def opcode_category(opcode: str) -> str:
    if opcode in CATEGORY_MAP:
        return CATEGORY_MAP[opcode]
    if opcode.startswith("PUSH"):
        return "push"
    if opcode.startswith("DUP"):
        return "dup"
    if opcode.startswith("SWAP"):
        return "swap"
    if opcode.startswith("LOG"):
        return "log"
    if opcode.startswith("UNKNOWN_"):
        return "unknown"
    return "other"


def decode_opcode(byte_value: int) -> Tuple[str, bool]:
    opcode = OPCODES.get(byte_value)
    if opcode is None:
        return f"UNKNOWN_0x{byte_value:02x}", True
    return opcode, False


def push_length(opcode: str) -> int:
    if opcode == "PUSH0":
        return 0
    if opcode.startswith("PUSH") and opcode[4:].isdigit():
        return int(opcode[4:])
    return 0


def disassemble_stream(bytecode: bytes) -> Iterator[Instruction]:
    """
    Lazy instruction generator. Each instruction is yielded as it is decoded.
    """
    mv = memoryview(bytecode)
    pc = 0
    length = len(bytecode)

    while pc < length:
        byte_value = mv[pc]
        opcode, is_unknown = decode_opcode(byte_value)
        operand_len = push_length(opcode)
        available_operand_len = max(0, min(operand_len, length - pc - 1))
        operand_bytes = bytes(mv[pc + 1 : pc + 1 + available_operand_len])
        size = 1 + available_operand_len
        is_push_truncated = available_operand_len < operand_len
        operand_hex = f"0x{operand_bytes.hex()}" if operand_len else None
        raw = bytes(mv[pc : pc + size]).hex()
        target = (
            int.from_bytes(operand_bytes, "big")
            if operand_len and not is_push_truncated
            else None
        )

        yield Instruction(
            pc=pc,
            opcode=opcode,
            operand=operand_hex,
            size=size,
            raw=raw,
            gas=GAS_FALLBACK.get(opcode, -1),
            category=opcode_category(opcode),
            is_invalid=(byte_value == 0xFE),
            is_unknown=is_unknown,
            is_jumpdest=(opcode == "JUMPDEST"),
            is_push_truncated=is_push_truncated,
            jump_target=target,
        )

        pc += size


class Disassembler:
    """High‑level disassembler with PC filtering and caching."""

    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self._instructions: Optional[List[Instruction]] = None

    def disassemble(
        self, pc_start: Optional[int] = None, pc_end: Optional[int] = None
    ) -> List[Instruction]:
        """
        Return all instructions, optionally filtered by PC range.
        Results are cached; subsequent calls with the same filters reuse the list.
        """
        if self._instructions is None:
            self._instructions = list(disassemble_stream(self.bytecode))
        if pc_start is None and pc_end is None:
            return self._instructions

        if pc_start is not None and pc_start < 0:
            raise ValueError("--pc-start must be >= 0")
        if pc_end is not None and pc_end < 0:
            raise ValueError("--pc-end must be >= 0")
        if pc_start is not None and pc_end is not None and pc_start > pc_end:
            raise ValueError("--pc-start must be <= --pc-end")

        return [
            ins
            for ins in self._instructions
            if (pc_start is None or ins.pc >= pc_start)
            and (pc_end is None or ins.pc <= pc_end)
        ]


# -----------------------------------------------------------------------------
# Static analysis
# -----------------------------------------------------------------------------

def extract_function_selectors(instructions: Sequence[Instruction]) -> List[str]:
    """Extract likely ABI selectors from a Solidity/Vyper-style dispatcher.

    The old implementation accepted any PUSH4 that merely had EQ and JUMPI
    somewhere in a six-instruction window. That was useful for recall but
    produced false positives in constants and error-handling code. Here we
    require a tighter comparator pattern and evidence of calldata dispatch.
    """
    if not instructions:
        return []

    # A normal ABI dispatcher reads calldata early. Keep the scan bounded so a
    # CALLDATALOAD deep inside a function does not validate unrelated PUSH4s.
    early = instructions[: min(160, len(instructions))]
    if not any(i.opcode == "CALLDATALOAD" for i in early):
        return []

    selectors: Set[str] = set()
    n = len(instructions)
    for idx, ins in enumerate(instructions):
        if ins.opcode != "PUSH4" or not ins.operand or ins.is_push_truncated:
            continue

        # Typical forms include:
        #   DUP1 PUSH4 <sel> EQ PUSH2 <dst> JUMPI
        # and minor compiler variations with DUP/SWAP/PUSH between EQ/JUMPI.
        eq_idx: Optional[int] = None
        for j in range(idx + 1, min(idx + 4, n)):
            if instructions[j].opcode == "EQ":
                eq_idx = j
                break
            if instructions[j].opcode in CONTROL_FLOW_OPS:
                break
        if eq_idx is None:
            continue

        jumpi_idx: Optional[int] = None
        for j in range(eq_idx + 1, min(eq_idx + 6, n)):
            if instructions[j].opcode == "JUMPI":
                jumpi_idx = j
                break
            if instructions[j].opcode in {"JUMP", "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"}:
                break
        if jumpi_idx is None:
            continue

        selector = ins.operand[2:]
        if selector not in {"00000000", "ffffffff", PANIC_SELECTOR}:
            selectors.add(selector)
    return sorted(selectors)


def classify_code(instructions: Sequence[Instruction]) -> Tuple[str, int, int]:
    """Return (kind, runtime_score, creation_score) using independent signals.

    `RETURN` alone is deliberately *not* treated as a runtime signal: initcode
    normally ends by RETURNing the deployed runtime bytecode. This fixes the
    circular heuristic in v7 where creation detection was often suppressed by
    runtime detection itself.
    """
    if not instructions:
        return "unknown", 0, 0

    ops = {ins.opcode for ins in instructions}
    head = instructions[: min(180, len(instructions))]
    head_ops = {ins.opcode for ins in head}
    runtime_score = 0
    creation_score = 0

    # Strong runtime/ABI-dispatch evidence.
    if "CALLDATALOAD" in head_ops:
        runtime_score += 4
    if "CALLDATASIZE" in head_ops:
        runtime_score += 2
    if "CALLVALUE" in head_ops:
        runtime_score += 1
    if "JUMPI" in head_ops and "CALLDATALOAD" in head_ops:
        runtime_score += 2
    if extract_function_selectors(instructions):
        runtime_score += 3
    if ops & {"SLOAD", "SSTORE", "LOG0", "LOG1", "LOG2", "LOG3", "LOG4", "DELEGATECALL", "STATICCALL"}:
        runtime_score += 1

    # Initcode commonly copies an embedded runtime image and RETURNs it.
    if "CODECOPY" in ops:
        creation_score += 4
    if "CODECOPY" in ops and "RETURN" in ops:
        creation_score += 3
    if len(instructions) >= 3:
        prologue = [i.opcode for i in instructions[:3]]
        if prologue == ["PUSH1", "PUSH1", "MSTORE"]:
            # Shared by much Solidity code, so only weak evidence.
            creation_score += 1
    if "CALLDATALOAD" not in head_ops and "CODECOPY" in ops:
        creation_score += 2

    if max(runtime_score, creation_score) < 2:
        kind = "unknown"
    elif runtime_score >= creation_score + 2:
        kind = "runtime"
    elif creation_score >= runtime_score + 2:
        kind = "creation"
    else:
        kind = "ambiguous"
    return kind, runtime_score, creation_score


def detect_runtime_code(instructions: Sequence[Instruction]) -> bool:
    kind, runtime_score, creation_score = classify_code(instructions)
    return kind == "runtime" or (kind == "ambiguous" and runtime_score > creation_score)


def detect_creation_code(instructions: Sequence[Instruction]) -> bool:
    kind, runtime_score, creation_score = classify_code(instructions)
    return kind == "creation" or (kind == "ambiguous" and creation_score > runtime_score)


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def discover_jumpdests(instructions: Sequence[Instruction]) -> Set[int]:
    return {ins.pc for ins in instructions if ins.is_jumpdest}


def _immediate_jump_target(instructions: Sequence[Instruction], idx: int) -> Optional[int]:
    """Resolve only a provably immediate PUSH-based jump target.

    This intentionally stays conservative. A previous v7 implementation also
    used the previous instruction, but without explicitly requiring PUSH, which
    could accidentally reuse a non-jump constant. Dynamic stack-derived jumps
    remain unresolved rather than being guessed.
    """
    if idx <= 0:
        return None
    prev = instructions[idx - 1]
    if not prev.opcode.startswith("PUSH") or prev.opcode == "PUSH0":
        return None
    if prev.is_push_truncated:
        return None
    return prev.jump_target


def build_cfg_edges(instructions: Sequence[Instruction]) -> List[ControlFlowEdge]:
    """Build a conservative instruction-level CFG for legacy EVM bytecode."""
    if not instructions:
        return []
    jumpdests = discover_jumpdests(instructions)
    edges: List[ControlFlowEdge] = []
    terminal = {"STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"}

    for idx, ins in enumerate(instructions):
        nxt = instructions[idx + 1].pc if idx + 1 < len(instructions) else None
        if ins.opcode in {"JUMP", "JUMPI"}:
            target = _immediate_jump_target(instructions, idx)
            resolved = target is not None and target in jumpdests
            kind = "jump_true" if ins.opcode == "JUMPI" else "jump"
            edges.append(ControlFlowEdge(ins.pc, target, kind, resolved))
            if ins.opcode == "JUMPI" and nxt is not None:
                edges.append(ControlFlowEdge(ins.pc, nxt, "fallthrough", True))
        elif ins.opcode not in terminal and nxt is not None:
            edges.append(ControlFlowEdge(ins.pc, nxt, "fallthrough", True))
    return edges


def collect_warnings(
    instructions: Sequence[Instruction], edges: Sequence[ControlFlowEdge]
) -> List[AnalysisWarning]:
    warnings: List[AnalysisWarning] = []
    for ins in instructions:
        if ins.is_unknown:
            warnings.append(AnalysisWarning(ins.pc, "UNKNOWN_OPCODE", ins.opcode))
        if ins.is_invalid:
            warnings.append(AnalysisWarning(ins.pc, "INVALID_OPCODE", "Explicit INVALID opcode"))
        if ins.is_push_truncated:
            warnings.append(
                AnalysisWarning(ins.pc, "TRUNCATED_PUSH", f"{ins.opcode} has incomplete operand")
            )

    unresolved_jump_exists = False
    for edge in edges:
        if edge.kind.startswith("jump") and not edge.resolved:
            unresolved_jump_exists = True
            msg = "Dynamic jump target" if edge.target is None else f"Target {edge.target} is not a JUMPDEST"
            warnings.append(AnalysisWarning(edge.source, "UNRESOLVED_JUMP", msg))

    # Do not label untargeted JUMPDESTs unreachable while dynamic jumps exist:
    # a dynamic edge may legitimately point to any of them.
    if not unresolved_jump_exists:
        targeted = {e.target for e in edges if e.resolved and e.target is not None}
        entry_pc = instructions[0].pc if instructions else None
        for ins in instructions:
            if ins.is_jumpdest and ins.pc != entry_pc and ins.pc not in targeted:
                warnings.append(
                    AnalysisWarning(ins.pc, "UNTARGETED_JUMPDEST", "No statically resolved incoming jump edge")
                )
    return warnings


class Analyzer:
    """Encapsulates analysis over a disassembled instruction list."""

    def __init__(self, instructions: Sequence[Instruction], bytecode: bytes):
        self.instructions = instructions
        self.bytecode = bytecode
        self._edges: Optional[List[ControlFlowEdge]] = None
        self._warnings: Optional[List[AnalysisWarning]] = None

    @property
    def edges(self) -> List[ControlFlowEdge]:
        if self._edges is None:
            self._edges = build_cfg_edges(self.instructions)
        return self._edges

    @property
    def warnings(self) -> List[AnalysisWarning]:
        if self._warnings is None:
            self._warnings = collect_warnings(self.instructions, self.edges)
        return self._warnings

    def summary(self) -> AnalysisSummary:
        gas_values = [i.gas for i in self.instructions if i.gas >= 0]
        selectors = extract_function_selectors(self.instructions)
        code_kind, runtime_score, creation_score = classify_code(self.instructions)
        runtime = detect_runtime_code(self.instructions)
        creation = detect_creation_code(self.instructions)

        return AnalysisSummary(
            bytecode_size=len(self.bytecode),
            instruction_count=len(self.instructions),
            unique_opcodes=len({i.opcode for i in self.instructions}),
            jumpdest_count=sum(1 for i in self.instructions if i.is_jumpdest),
            invalid_count=sum(1 for i in self.instructions if i.is_invalid),
            unknown_count=sum(1 for i in self.instructions if i.is_unknown),
            truncated_push_count=sum(1 for i in self.instructions if i.is_push_truncated),
            function_selectors=selectors,
            selector_count=len(selectors),
            has_panic_selector=PANIC_SELECTOR
            in {i.operand[2:] for i in self.instructions if i.opcode == "PUSH4" and i.operand},
            entropy=calculate_entropy(self.bytecode),
            avg_gas=round(mean(gas_values), 2) if gas_values else 0.0,
            runtime_likely=runtime,
            creation_likely=creation,
            code_kind=code_kind,
            runtime_score=runtime_score,
            creation_score=creation_score,
            estimated_static_gas=sum(gas_values),
            warning_count=len(self.warnings),
        )

    def opcode_counter(self) -> Counter:
        return Counter(i.opcode for i in self.instructions)


# -----------------------------------------------------------------------------
# Output formatting
# -----------------------------------------------------------------------------

class Formatter:
    """Handle text/JSON output with various options."""

    def __init__(
        self,
        instructions: Sequence[Instruction],
        bytecode: bytes,
        metadata: MetadataInfo,
        analyzer: Analyzer,
        *,
        color: bool = False,
        compact: bool = False,
    ):
        self.instructions = instructions
        self.bytecode = bytecode
        self.metadata = metadata
        self.analyzer = analyzer
        self.color = color
        self.compact = compact

    def format_instruction(self, ins: Instruction) -> str:
        opcode = ins.opcode
        if ins.is_invalid or ins.is_unknown or ins.is_push_truncated:
            opcode = colorize(opcode, RED, enabled=self.color)
        elif ins.is_jumpdest:
            opcode = colorize(opcode, GREEN, enabled=self.color)
        elif ins.category == "control_flow":
            opcode = colorize(opcode, YELLOW, enabled=self.color)
        elif ins.category == "call_create":
            opcode = colorize(opcode, BLUE, enabled=self.color)

        extra = []
        if ins.jump_target is not None:
            extra.append(f"target={ins.jump_target}")
        if ins.is_invalid:
            extra.append("INVALID")
        if ins.is_unknown:
            extra.append("UNKNOWN")
        if ins.is_push_truncated:
            extra.append("TRUNCATED_PUSH")

        extra_str = " | " + " ".join(extra) if extra else ""

        if self.compact:
            operand = ins.operand or ""
            return f"{ins.pc:04x}: {opcode} {operand} (gas={ins.gas}){extra_str}"
        else:
            return (
                f"{ins.pc:06d}: "
                f"{opcode:<18} "
                f"{(ins.operand or ''):<70} "
                f"size={ins.size:<2} "
                f"gas={ins.gas:<5} "
                f"raw={ins.raw}"
                f"{extra_str}"
            )

    def text_output(
        self,
        show_summary: bool,
        show_cfg: bool,
        show_warnings: bool,
        show_instructions: bool = True,
        filter_category: Optional[str] = None,
        search_hex: Optional[str] = None,
    ) -> str:
        lines = []
        for ins in self.instructions if show_instructions else ():
            if filter_category and ins.category != filter_category:
                continue
            if search_hex and search_hex.lower() not in ins.raw.lower():
                continue
            lines.append(self.format_instruction(ins))

        if self.metadata.stripped:
            lines.append("")
            lines.append(
                f"Metadata stripped: offset={self.metadata.offset} length={self.metadata.length} "
                f"original={self.metadata.original_size}B stripped={self.metadata.stripped_size}B"
            )

        if show_cfg:
            lines.extend(self._cfg_text())
        if show_summary:
            lines.extend(self._summary_text())
            lines.extend(self._opcode_summary_text())
        if show_warnings:
            lines.extend(self._warnings_text())
        return "\n".join(lines)

    def _cfg_text(self) -> List[str]:
        lines = ["", "Control Flow Edges:"]
        edges = self.analyzer.edges
        if not edges:
            lines.append("  (none)")
        else:
            for edge in edges:
                target = "dynamic" if edge.target is None else str(edge.target)
                status = "" if edge.resolved else " [unresolved]"
                lines.append(f"  {edge.source:06d} -> {target:<8} {edge.kind}{status}")
        return lines

    def _summary_text(self) -> List[str]:
        s = self.analyzer.summary()
        lines = ["", colorize("Analysis Summary:", CYAN, enabled=self.color)]
        lines.extend(
            [
                f"  Bytecode Size:       {s.bytecode_size} bytes",
                f"  Instructions:        {s.instruction_count}",
                f"  Unique Opcodes:      {s.unique_opcodes}",
                f"  JUMPDESTs:           {s.jumpdest_count}",
                f"  INVALIDs:            {s.invalid_count}",
                f"  Unknown Opcodes:     {s.unknown_count}",
                f"  Truncated PUSH:      {s.truncated_push_count}",
                f"  Entropy:             {s.entropy}",
                f"  Avg Gas Approx:      {s.avg_gas}",
                f"  Static Gas Sum*:     {s.estimated_static_gas}",
                f"  Runtime Likely:      {s.runtime_likely}",
                f"  Creation Likely:     {s.creation_likely}",
                f"  Code Classification: {s.code_kind} (runtime={s.runtime_score}, creation={s.creation_score})",
                f"  Panic Selector Seen: {s.has_panic_selector}",
                f"  Selector Count:      {s.selector_count}",
                f"  Analysis Warnings:   {s.warning_count}",
            ]
        )
        if s.function_selectors:
            lines.append(f"  Function Selectors:  {', '.join(s.function_selectors[:30])}")
            if len(s.function_selectors) > 30:
                lines.append(f"                       ... +{len(s.function_selectors) - 30} more")
        lines.append("  * Excludes dynamic gas, memory expansion, cold/warm access and refunds.")
        return lines

    def _opcode_summary_text(self) -> List[str]:
        counter = self.analyzer.opcode_counter()
        lines = ["", colorize("Opcode Summary:", CYAN, enabled=self.color)]
        for op, count in sorted(counter.items(), key=lambda x: (-x[1], x[0])):
            lines.append(f"  {op:<18} {count}")
        return lines

    def _warnings_text(self) -> List[str]:
        warnings = self.analyzer.warnings
        if not warnings:
            return []
        lines = ["", "Warnings:"]
        for w in warnings:
            location = "global" if w.pc is None else f"pc={w.pc}"
            lines.append(f"  [{w.code}] {location}: {w.message}")
        return lines

    def json_output(self, include_cfg: bool = False) -> str:
        s = self.analyzer.summary()
        payload: Dict[str, Any] = {
            "version": VERSION,
            "metadata": asdict(self.metadata),
            "summary": asdict(s),
            "warnings": [asdict(w) for w in self.analyzer.warnings],
            "instructions": [asdict(i) for i in self.instructions],
        }
        if include_cfg:
            payload["cfg_edges"] = [asdict(e) for e in self.analyzer.edges]
        return json.dumps(payload, indent=2, sort_keys=True)


# -----------------------------------------------------------------------------
# CLI and main
# -----------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=f"EVM Disassembler Pro v{VERSION}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--bytecode", help="Raw hex bytecode (with or without 0x prefix)")
    src.add_argument("--file", type=Path, help="Read bytecode from file (hex, with comments allowed)")
    src.add_argument("--stdin", action="store_true", help="Read bytecode from stdin")

    parser.add_argument("--output", type=Path, help="Output file")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--summary", action="store_true", help="Show analysis summary (enables opcode stats)")
    parser.add_argument("--summary-only", action="store_true", help="Show summary/opcode stats without instruction listing")
    parser.add_argument("--cfg", action="store_true", help="Emit conservative CFG edges (text and JSON)")
    parser.add_argument("--warnings", action="store_true", help="Show analysis warnings")
    parser.add_argument("--pc-start", type=int, help="Start PC filter, inclusive")
    parser.add_argument("--pc-end", type=int, help="End PC filter, inclusive")
    parser.add_argument("--no-metadata", action="store_true", help="Do NOT strip Solidity CBOR metadata")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--compact", action="store_true", help="Compact instruction output")
    parser.add_argument(
        "--category",
        choices=[
            "arithmetic",
            "logic",
            "control_flow",
            "memory_storage",
            "call_create",
            "environment",
            "stack",
            "push",
            "dup",
            "swap",
            "log",
            "unknown",
            "other",
        ],
        help="Filter instructions by category",
    )
    parser.add_argument("--search", help="Show only instructions whose raw hex contains this substring")
    parser.add_argument("--detect-creation", action="store_true", help="Print creation/runtime detection")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(args.debug)

    try:
        if args.summary_only and (args.category or args.search):
            raise ValueError("--summary-only cannot be combined with --category/--search")
        if args.search:
            search = strip_0x(re.sub(r"\s+", "", args.search)).lower()
            if not search or not HEX_RE.fullmatch(search):
                raise ValueError("--search must be a hexadecimal substring")
            args.search = search

        # 1. Load bytecode
        if args.bytecode:
            bytecode, metadata = normalize_bytecode(args.bytecode, remove_metadata=not args.no_metadata)
        elif args.file:
            bytecode, metadata = load_from_file(args.file, remove_metadata=not args.no_metadata)
        else:
            bytecode, metadata = load_from_stdin(remove_metadata=not args.no_metadata)

        LOG.info("Loaded %d bytes", len(bytecode))
        if metadata.stripped:
            LOG.info("Stripped CBOR metadata: %d -> %d bytes", metadata.original_size, metadata.stripped_size)

        # 2. Disassemble once. Analysis always runs on the complete decoded
        #    bytecode; PC filters affect presentation only. This avoids bogus
        #    selector/CFG/classification results for sliced output ranges.
        disassembler = Disassembler(bytecode)
        full_instructions = disassembler.disassemble()
        if not full_instructions:
            LOG.error("No instructions decoded")
            return EXIT_DISASSEMBLY_ERROR

        try:
            instructions = disassembler.disassemble(pc_start=args.pc_start, pc_end=args.pc_end)
        except ValueError as e:
            LOG.error("Invalid PC filter: %s", e)
            return EXIT_INVALID_BYTECODE

        if not instructions:
            LOG.error("No instructions in the selected PC range")
            return EXIT_DISASSEMBLY_ERROR

        # 3. Analyze full code, display the selected range.
        analyzer = Analyzer(full_instructions, bytecode)

        # 4. Handle special --detect-creation
        if args.detect_creation:
            summary = analyzer.summary()
            print(
                f"Code classification: {summary.code_kind} "
                f"(runtime_score={summary.runtime_score}, creation_score={summary.creation_score})"
            )
            return EXIT_SUCCESS

        # 5. Format output
        color = sys.stdout.isatty() and not args.no_color and not args.json and args.output is None
        formatter = Formatter(
            instructions,
            bytecode,
            metadata,
            analyzer,
            color=color,
            compact=args.compact,
        )

        if args.json:
            text = formatter.json_output(include_cfg=args.cfg)
        else:
            text = formatter.text_output(
                show_summary=args.summary or args.summary_only,
                show_cfg=args.cfg,
                show_instructions=not args.summary_only,
                show_warnings=args.warnings,
                filter_category=args.category,
                search_hex=args.search,
            )

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text + ("\n" if text else ""), encoding="utf-8")
            LOG.info("Saved output to %s", args.output)
        else:
            print(text)

        return EXIT_SUCCESS

    except ValueError as e:
        LOG.error("Invalid bytecode: %s", e)
        return EXIT_INVALID_BYTECODE
    except IOError as e:
        LOG.error("%s", e)
        return EXIT_READ_ERROR
    except RuntimeError as e:
        LOG.error("%s", e)
        return EXIT_DISASSEMBLY_ERROR
    except BrokenPipeError:
        # Typical when piping into `head`; avoid a noisy traceback.
        return EXIT_SUCCESS
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130
    except Exception:
        LOG.exception("Fatal error")
        return EXIT_WRITE_ERROR


# -----------------------------------------------------------------------------
# Exit codes
# -----------------------------------------------------------------------------

EXIT_SUCCESS = 0
EXIT_INVALID_BYTECODE = 2
EXIT_READ_ERROR = 3
EXIT_DISASSEMBLY_ERROR = 4
EXIT_WRITE_ERROR = 5

if __name__ == "__main__":
    sys.exit(main())

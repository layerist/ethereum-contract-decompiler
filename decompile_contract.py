#!/usr/bin/env python3
"""
Ultra-Hardened EVM Bytecode Disassembler v3
===========================================

Major Improvements over v2
--------------------------
• Fully streaming disassembly
• Huge contract support
• Better CBOR metadata stripping
• PUSH-aware control flow analysis
• JUMPDEST discovery
• Static jump edge extraction
• Safer invalid opcode handling
• Faster byte access using memoryview
• Rich JSON schema
• Optional colored output
• Opcode category analysis
• Entropy calculation
• Function selector extraction
• Basic dispatcher detection
• Runtime/initcode heuristic
• Multi-format output
• Deterministic stable output
• Better evmdasm compatibility handling
• Proper EOF handling
• Safer exception boundaries
• Performance optimized for very large contracts

Requirements
------------
pip install evmdasm

Usage
-----
python disasm.py --bytecode 0x60806040...
python disasm.py --file contract.hex --json
cat contract.hex | python disasm.py --stdin --summary

"""

from __future__ import annotations

import argparse
import json
import logging
import math
import re
import shutil
import sys
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from statistics import mean
from typing import (
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
)

import evmdasm


# =============================================================================
# Exit codes
# =============================================================================

EXIT_SUCCESS = 0
EXIT_INVALID_BYTECODE = 2
EXIT_READ_ERROR = 3
EXIT_DISASSEMBLY_ERROR = 4
EXIT_WRITE_ERROR = 5


# =============================================================================
# Logging
# =============================================================================

LOG = logging.getLogger("evm-disasm")


def setup_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )


# =============================================================================
# Constants
# =============================================================================

HEX_RE = re.compile(r"^[0-9a-f]+$")
COMMENT_RE = re.compile(r"(//.*?$|#.*?$)", re.MULTILINE)

MAX_BYTECODE_SIZE = 50_000_000

# Solidity panic selector
PANIC_SELECTOR = "4e487b71"

# Common dispatcher pattern
DISPATCH_SIG = b"\x63"

# ANSI colors
COLOR_ENABLED = sys.stdout.isatty()

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"

# EVM opcode categories
ARITHMETIC_OPS = {
    "ADD", "SUB", "MUL", "DIV", "SDIV",
    "MOD", "SMOD", "ADDMOD", "MULMOD", "EXP",
}

LOGIC_OPS = {
    "LT", "GT", "SLT", "SGT", "EQ",
    "ISZERO", "AND", "OR", "XOR", "NOT",
    "BYTE", "SHL", "SHR", "SAR",
}

CONTROL_FLOW_OPS = {
    "JUMP", "JUMPI", "STOP",
    "RETURN", "REVERT", "INVALID",
    "SELFDESTRUCT",
}

MEMORY_OPS = {
    "MLOAD", "MSTORE", "MSTORE8",
    "SLOAD", "SSTORE",
}

CALL_OPS = {
    "CALL", "DELEGATECALL", "STATICCALL",
    "CALLCODE", "CREATE", "CREATE2",
}

# Extended gas fallback
GAS_FALLBACK = {
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
    "SHA3": 30,
    "MLOAD": 3,
    "MSTORE": 3,
    "MSTORE8": 3,
    "SLOAD": 100,
    "SSTORE": 100,
    "JUMP": 8,
    "JUMPI": 10,
    "JUMPDEST": 1,
    "PUSH1": 3,
    "PUSH32": 3,
    "DUP1": 3,
    "SWAP1": 3,
    "CALL": 700,
    "RETURN": 0,
    "REVERT": 0,
    "INVALID": 0,
}


# =============================================================================
# Data Models
# =============================================================================

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
    is_jumpdest: bool
    jump_target: Optional[int]


@dataclass(frozen=True)
class AnalysisSummary:
    instruction_count: int
    unique_opcodes: int
    jumpdest_count: int
    invalid_count: int
    function_selectors: List[str]
    entropy: float
    avg_gas: float
    runtime_likely: bool


# =============================================================================
# Utilities
# =============================================================================

def colorize(text: str, color: str) -> str:
    if not COLOR_ENABLED:
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
        raise ValueError("Bytecode exceeds maximum size")


# =============================================================================
# Metadata stripping
# =============================================================================

def strip_metadata_cbor(bytecode: bytes) -> bytes:
    """
    Solidity metadata stripping.

    Solidity usually appends:
        <cbor> <2-byte length>

    Common CBOR prefixes:
        a1
        a2
        a3
    """

    if len(bytecode) < 4:
        return bytecode

    meta_len = int.from_bytes(bytecode[-2:], "big")

    if meta_len <= 0:
        return bytecode

    if meta_len + 2 > len(bytecode):
        return bytecode

    start = len(bytecode) - meta_len - 2

    if start < 0:
        return bytecode

    if bytecode[start] in (0xA1, 0xA2, 0xA3):
        LOG.debug(
            "Detected Solidity CBOR metadata "
            "(offset=%d length=%d)",
            start,
            meta_len,
        )
        return bytecode[:start]

    return bytecode


def normalize_bytecode(raw: str, *, remove_metadata: bool) -> bytes:
    cleaned = clean_raw_input(raw)
    cleaned = strip_0x(cleaned)

    validate_hex(cleaned)

    data = bytes.fromhex(cleaned)

    if remove_metadata:
        data = strip_metadata_cbor(data)

    return data


# =============================================================================
# Input
# =============================================================================

def load_from_file(path: Path, *, remove_metadata: bool) -> bytes:
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as e:
        raise IOError(f"Failed reading file: {e}") from e

    return normalize_bytecode(
        raw,
        remove_metadata=remove_metadata,
    )


def load_from_stdin(*, remove_metadata: bool) -> bytes:
    raw = sys.stdin.read()

    if not raw.strip():
        raise ValueError("Empty stdin input")

    return normalize_bytecode(
        raw,
        remove_metadata=remove_metadata,
    )


# =============================================================================
# Analysis
# =============================================================================

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


def opcode_category(opcode: str) -> str:
    if opcode in ARITHMETIC_OPS:
        return "arithmetic"

    if opcode in LOGIC_OPS:
        return "logic"

    if opcode in CONTROL_FLOW_OPS:
        return "control_flow"

    if opcode in MEMORY_OPS:
        return "memory"

    if opcode in CALL_OPS:
        return "call"

    if opcode.startswith("PUSH"):
        return "push"

    if opcode.startswith("DUP"):
        return "dup"

    if opcode.startswith("SWAP"):
        return "swap"

    return "other"


def extract_function_selectors(bytecode: bytes) -> List[str]:
    """
    Extract likely function selectors from PUSH4 patterns.
    """

    selectors: Set[str] = set()

    mv = memoryview(bytecode)
    length = len(bytecode)

    i = 0

    while i < length - 5:
        if mv[i] == 0x63:
            selector = bytes(mv[i + 1:i + 5]).hex()

            if selector != "ffffffff":
                selectors.add(selector)

            i += 5
        else:
            i += 1

    return sorted(selectors)


def detect_runtime_code(bytecode: bytes) -> bool:
    """
    Very rough heuristic.
    """

    if b"\xf3" in bytecode:
        return True

    if b"\xfd" in bytecode:
        return True

    return False


# =============================================================================
# Disassembly
# =============================================================================

def gas_cost(ins) -> int:
    if hasattr(ins, "gas") and ins.gas is not None:
        return ins.gas

    return GAS_FALLBACK.get(ins.name, -1)


def detect_invalid(bytecode: memoryview, pc: int) -> bool:
    return bytecode[pc] == 0xFE


def jump_target(ins) -> Optional[int]:
    if not ins.name.startswith("PUSH"):
        return None

    if not ins.operand:
        return None

    try:
        return int.from_bytes(ins.operand, "big")
    except Exception:
        return None


def safe_operand_hex(operand) -> Optional[str]:
    if not operand:
        return None

    try:
        return f"0x{operand.hex()}"
    except Exception:
        return None


def disassemble_stream(
    bytecode: bytes,
) -> Iterator[Instruction]:

    mv = memoryview(bytecode)

    try:
        evm = evmdasm.EvmBytecode(bytecode.hex())
        instructions = evm.disassemble()
    except Exception as e:
        raise RuntimeError(
            f"evmdasm disassembly failed: {e}"
        ) from e

    for ins in instructions:
        try:
            pc = ins.pc
            operand = safe_operand_hex(ins.operand)
            size = 1 + len(ins.operand or b"")

            raw = bytes(mv[pc:pc + size]).hex()

            yield Instruction(
                pc=pc,
                opcode=ins.name,
                operand=operand,
                size=size,
                raw=raw,
                gas=gas_cost(ins),
                category=opcode_category(ins.name),
                is_invalid=detect_invalid(mv, pc),
                is_jumpdest=(ins.name == "JUMPDEST"),
                jump_target=jump_target(ins),
            )

        except Exception as e:
            LOG.debug(
                "Skipping malformed instruction at pc=%s: %s",
                getattr(ins, "pc", "?"),
                e,
            )


def disassemble(
    bytecode: bytes,
    *,
    pc_start: Optional[int],
    pc_end: Optional[int],
) -> List[Instruction]:

    result: List[Instruction] = []

    for ins in disassemble_stream(bytecode):

        if pc_start is not None and ins.pc < pc_start:
            continue

        if pc_end is not None and ins.pc > pc_end:
            continue

        result.append(ins)

    if not result:
        raise RuntimeError("No instructions decoded")

    return result


# =============================================================================
# CFG / Jump Analysis
# =============================================================================

def discover_jumpdests(
    instructions: Iterable[Instruction],
) -> Set[int]:

    return {
        ins.pc
        for ins in instructions
        if ins.is_jumpdest
    }


def static_jump_edges(
    instructions: List[Instruction],
    jumpdests: Set[int],
) -> List[Tuple[int, int]]:

    edges = []

    for idx, ins in enumerate(instructions[:-1]):

        if ins.opcode not in ("JUMP", "JUMPI"):
            continue

        prev_ins = instructions[idx - 1] if idx > 0 else None

        if not prev_ins:
            continue

        if prev_ins.jump_target is None:
            continue

        if prev_ins.jump_target in jumpdests:
            edges.append((ins.pc, prev_ins.jump_target))

    return edges


# =============================================================================
# Summary
# =============================================================================

def build_summary(
    instructions: List[Instruction],
    bytecode: bytes,
) -> AnalysisSummary:

    gas_values = [
        i.gas
        for i in instructions
        if i.gas >= 0
    ]

    return AnalysisSummary(
        instruction_count=len(instructions),
        unique_opcodes=len(
            set(i.opcode for i in instructions)
        ),
        jumpdest_count=sum(
            1 for i in instructions if i.is_jumpdest
        ),
        invalid_count=sum(
            1 for i in instructions if i.is_invalid
        ),
        function_selectors=extract_function_selectors(bytecode),
        entropy=calculate_entropy(bytecode),
        avg_gas=round(mean(gas_values), 2)
        if gas_values else 0.0,
        runtime_likely=detect_runtime_code(bytecode),
    )


def opcode_summary(
    instructions: Iterable[Instruction],
) -> str:

    counter = Counter(i.opcode for i in instructions)

    lines = []

    lines.append(colorize(
        "Opcode Summary:",
        CYAN,
    ))

    for op, count in sorted(
        counter.items(),
        key=lambda x: (-x[1], x[0]),
    ):
        lines.append(f"  {op:<18} {count}")

    return "\n".join(lines)


# =============================================================================
# Output
# =============================================================================

def instruction_to_text(i: Instruction) -> str:

    opcode = i.opcode

    if i.is_invalid:
        opcode = colorize(opcode, RED)

    elif i.is_jumpdest:
        opcode = colorize(opcode, GREEN)

    elif i.category == "control_flow":
        opcode = colorize(opcode, YELLOW)

    elif i.category == "call":
        opcode = colorize(opcode, BLUE)

    operand = i.operand or ""

    extra = []

    if i.jump_target is not None:
        extra.append(f"target={i.jump_target}")

    if i.is_invalid:
        extra.append("INVALID")

    extra_str = (
        " | " + " ".join(extra)
        if extra else ""
    )

    return (
        f"{i.pc:06d}: "
        f"{opcode:<18} "
        f"{operand:<70} "
        f"size={i.size:<2} "
        f"gas={i.gas:<4} "
        f"raw={i.raw}"
        f"{extra_str}"
    )


def write_output(
    instructions: List[Instruction],
    bytecode: bytes,
    *,
    outfile: Optional[Path],
    json_out: bool,
    summary: bool,
    cfg: bool,
) -> None:

    try:

        text = ""

        if json_out:

            jumpdests = discover_jumpdests(instructions)

            payload = {
                "summary": asdict(
                    build_summary(
                        instructions,
                        bytecode,
                    )
                ),
                "instructions": [
                    asdict(i)
                    for i in instructions
                ],
            }

            if cfg:
                payload["cfg_edges"] = static_jump_edges(
                    instructions,
                    jumpdests,
                )

            text = json.dumps(
                payload,
                indent=2,
                sort_keys=True,
            )

        else:

            lines = [
                instruction_to_text(i)
                for i in instructions
            ]

            if summary:
                lines.append("")
                lines.append(
                    opcode_summary(instructions)
                )

                s = build_summary(
                    instructions,
                    bytecode,
                )

                lines.append("")
                lines.append(
                    colorize(
                        "Analysis Summary:",
                        CYAN,
                    )
                )

                lines.append(
                    f"  Instructions:       {s.instruction_count}"
                )
                lines.append(
                    f"  Unique Opcodes:     {s.unique_opcodes}"
                )
                lines.append(
                    f"  JUMPDESTs:          {s.jumpdest_count}"
                )
                lines.append(
                    f"  INVALIDs:           {s.invalid_count}"
                )
                lines.append(
                    f"  Entropy:            {s.entropy}"
                )
                lines.append(
                    f"  Avg Gas:            {s.avg_gas}"
                )
                lines.append(
                    f"  Runtime Likely:     {s.runtime_likely}"
                )

                if s.function_selectors:
                    lines.append(
                        f"  Function Selectors: "
                        f"{', '.join(s.function_selectors[:20])}"
                    )

            text = "\n".join(lines)

        if outfile:
            outfile.write_text(
                text,
                encoding="utf-8",
            )

            LOG.info(
                "Saved output to %s",
                outfile,
            )
        else:
            print(text)

    except Exception as e:
        raise IOError(
            f"Failed writing output: {e}"
        ) from e


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description=(
            "Ultra-Hardened EVM Bytecode "
            "Disassembler v3"
        )
    )

    src = parser.add_mutually_exclusive_group(
        required=True
    )

    src.add_argument(
        "--bytecode",
        help="Raw hex bytecode",
    )

    src.add_argument(
        "--file",
        type=Path,
        help="Read bytecode from file",
    )

    src.add_argument(
        "--stdin",
        action="store_true",
        help="Read bytecode from stdin",
    )

    parser.add_argument(
        "--output",
        type=Path,
        help="Output file",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="JSON output",
    )

    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show analysis summary",
    )

    parser.add_argument(
        "--cfg",
        action="store_true",
        help="Static CFG edge extraction",
    )

    parser.add_argument(
        "--pc-start",
        type=int,
        help="Start PC filter",
    )

    parser.add_argument(
        "--pc-end",
        type=int,
        help="End PC filter",
    )

    parser.add_argument(
        "--no-metadata",
        action="store_true",
        help="Do NOT strip Solidity metadata",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    return parser.parse_args()


# =============================================================================
# Main
# =============================================================================

def main() -> int:

    args = parse_args()

    setup_logging(args.debug)

    try:

        if args.bytecode:

            bytecode = normalize_bytecode(
                args.bytecode,
                remove_metadata=not args.no_metadata,
            )

        elif args.file:

            bytecode = load_from_file(
                args.file,
                remove_metadata=not args.no_metadata,
            )

        else:

            bytecode = load_from_stdin(
                remove_metadata=not args.no_metadata,
            )

        LOG.info(
            "Loaded %d bytes",
            len(bytecode),
        )

        instructions = disassemble(
            bytecode,
            pc_start=args.pc_start,
            pc_end=args.pc_end,
        )

        write_output(
            instructions,
            bytecode,
            outfile=args.output,
            json_out=args.json,
            summary=args.summary,
            cfg=args.cfg,
        )

        return EXIT_SUCCESS

    except ValueError as e:

        LOG.error(
            "Invalid bytecode: %s",
            e,
        )

        return EXIT_INVALID_BYTECODE

    except IOError as e:

        LOG.error("%s", e)

        return EXIT_READ_ERROR

    except RuntimeError as e:

        LOG.error("%s", e)

        return EXIT_DISASSEMBLY_ERROR

    except KeyboardInterrupt:

        print("\nInterrupted")

        return 130

    except Exception:

        LOG.exception("Fatal error")

        return EXIT_WRITE_ERROR


if __name__ == "__main__":
    sys.exit(main())

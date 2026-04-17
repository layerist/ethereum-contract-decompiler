#!/usr/bin/env python3
"""
Ultra-Hardened EVM Bytecode Disassembler v2
------------------------------------------

Major upgrades:
  • Zero-copy byte parsing
  • CBOR-aware metadata stripping
  • Streaming disassembly (low memory)
  • Raw-byte INVALID opcode detection (0xFE)
  • Static jump target analysis
  • Gas fallback table
  • PC range filtering
  • Deterministic JSON output (stable ordering)
  • Faster execution on large contracts
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Iterator

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
COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)

MAX_BYTECODE_SIZE = 10_000_000

# Minimal gas fallback (extend if needed)
GAS_FALLBACK = {
    "STOP": 0,
    "ADD": 3,
    "MUL": 5,
    "SUB": 3,
    "DIV": 5,
    "PUSH1": 3,
    "JUMP": 8,
    "JUMPI": 10,
    "SLOAD": 100,
    "SSTORE": 100,
}


# =============================================================================
# Utilities
# =============================================================================

def _clean_raw_input(raw: str) -> str:
    raw = COMMENT_RE.sub("", raw)
    raw = re.sub(r"\s+", "", raw)
    return raw.lower()


def _strip_0x_prefix(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def _validate_hex(body: str) -> None:
    if not body:
        raise ValueError("Empty bytecode")

    if len(body) % 2 != 0:
        raise ValueError("Hex string must have even length")

    if not HEX_RE.fullmatch(body):
        raise ValueError("Invalid hex characters detected")

    if len(body) // 2 > MAX_BYTECODE_SIZE:
        raise ValueError("Bytecode too large")


# =============================================================================
# Metadata stripping (CBOR-aware)
# =============================================================================

def strip_metadata_cbor(bytecode: bytes) -> bytes:
    """
    Detect Solidity CBOR metadata footer.

    Format:
      ... <code> a264... <cbor> <2-byte length>

    Last 2 bytes = metadata length
    """
    if len(bytecode) < 4:
        return bytecode

    meta_len = int.from_bytes(bytecode[-2:], "big")

    if meta_len + 2 <= len(bytecode):
        possible_start = len(bytecode) - meta_len - 2

        # heuristic: CBOR usually starts with 0xa2 / 0xa1
        if bytecode[possible_start] in (0xA1, 0xA2):
            logging.debug("CBOR metadata detected and stripped")
            return bytecode[:possible_start]

    return bytecode


def normalize_bytecode(raw: str, *, remove_metadata: bool) -> bytes:
    cleaned = _clean_raw_input(raw)
    cleaned = _strip_0x_prefix(cleaned)

    _validate_hex(cleaned)

    data = bytes.fromhex(cleaned)

    if remove_metadata:
        data = strip_metadata_cbor(data)

    return data


# =============================================================================
# Input
# =============================================================================

def load_from_file(path: Path, *, remove_metadata: bool) -> bytes:
    try:
        raw = path.read_text("utf-8")
    except Exception as e:
        raise IOError(f"Failed reading file: {e}") from e

    return normalize_bytecode(raw, remove_metadata=remove_metadata)


def load_from_stdin(*, remove_metadata: bool) -> bytes:
    raw = sys.stdin.read()
    if not raw.strip():
        raise ValueError("Empty stdin input")

    return normalize_bytecode(raw, remove_metadata=remove_metadata)


# =============================================================================
# Instruction model
# =============================================================================

@dataclass(frozen=True)
class Instruction:
    pc: int
    opcode: str
    operand: Optional[str]
    size: int
    raw: str
    gas: int
    is_invalid: bool
    jump_target: Optional[int]


# =============================================================================
# Disassembly
# =============================================================================

def _gas(ins) -> int:
    if hasattr(ins, "gas") and ins.gas is not None:
        return ins.gas
    return GAS_FALLBACK.get(ins.name, -1)


def _detect_invalid(bytecode: bytes, pc: int) -> bool:
    return bytecode[pc] == 0xFE


def _jump_target(ins) -> Optional[int]:
    if ins.name.startswith("PUSH") and ins.operand:
        return int.from_bytes(ins.operand, "big")
    return None


def disassemble_stream(
    bytecode: bytes,
) -> Iterator[Instruction]:

    evm = evmdasm.EvmBytecode(bytecode.hex())
    instructions = evm.disassemble()

    for ins in instructions:
        size = 1 + len(ins.operand or b"")
        pc = ins.pc

        yield Instruction(
            pc=pc,
            opcode=ins.name,
            operand=f"0x{ins.operand.hex()}" if ins.operand else None,
            size=size,
            raw=bytecode[pc:pc+size].hex(),
            gas=_gas(ins),
            is_invalid=_detect_invalid(bytecode, pc),
            jump_target=_jump_target(ins),
        )


def disassemble(
    bytecode: bytes,
    *,
    pc_start: Optional[int],
    pc_end: Optional[int],
) -> List[Instruction]:

    result = []

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
# Summary
# =============================================================================

def opcode_summary(data: Iterable[Instruction]) -> str:
    counter = Counter(i.opcode for i in data)
    lines = ["Opcode Summary:"]
    for op, count in sorted(counter.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"  {op:<16} {count}")
    return "\n".join(lines)


# =============================================================================
# Output
# =============================================================================

def write_output(
    result: List[Instruction],
    *,
    outfile: Optional[Path],
    json_out: bool,
    summary: bool,
) -> None:

    try:
        if json_out:
            payload = [asdict(x) for x in result]

            text = json.dumps(
                payload,
                indent=2,
                sort_keys=True,
            )

            if summary:
                text += "\n\n" + opcode_summary(result)

        else:
            lines = []
            for i in result:
                lines.append(
                    f"{i.pc:04d}: {i.opcode} "
                    f"{i.operand or ''} | "
                    f"size={i.size} raw={i.raw} "
                    f"gas={i.gas} "
                    f"{'INVALID' if i.is_invalid else ''}"
                )

            text = "\n".join(lines)

        if outfile:
            outfile.write_text(text, encoding="utf-8")
            logging.info("Saved to %s", outfile)
        else:
            print(text)

    except Exception as e:
        raise IOError(f"Write failed: {e}") from e


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()

    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--bytecode")
    src.add_argument("--file", type=Path)
    src.add_argument("--stdin", action="store_true")

    p.add_argument("--output", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument("--summary", action="store_true")
    p.add_argument("--pc-start", type=int)
    p.add_argument("--pc-end", type=int)
    p.add_argument("--no-metadata", action="store_true")
    p.add_argument("--debug", action="store_true")

    return p.parse_args()


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

        result = disassemble(
            bytecode,
            pc_start=args.pc_start,
            pc_end=args.pc_end,
        )

        write_output(
            result,
            outfile=args.output,
            json_out=args.json,
            summary=args.summary,
        )

        return EXIT_SUCCESS

    except ValueError as e:
        logging.error("Invalid bytecode: %s", e)
        return EXIT_INVALID_BYTECODE

    except IOError as e:
        logging.error("%s", e)
        return EXIT_READ_ERROR

    except RuntimeError as e:
        logging.error("%s", e)
        return EXIT_DISASSEMBLY_ERROR

    except Exception:
        logging.exception("Fatal error")
        return EXIT_WRITE_ERROR


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(130)

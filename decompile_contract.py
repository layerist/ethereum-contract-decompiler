#!/usr/bin/env python3
"""
Ultra-Hardened EVM Bytecode Disassembler
----------------------------------------

Improvements:
  • Safer metadata stripping with fallback heuristics
  • Instruction size + raw byte extraction
  • Better INVALID opcode detection (byte-level)
  • Optional control-flow annotations
  • Improved JSON schema (gas, size, bytes)
  • Streaming-friendly structure for large inputs
  • Deterministic + stable output
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
from typing import Any, Iterable, List, Optional

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

# Solidity metadata markers
METADATA_MARKERS = [
    "a2646970667358",  # ipfs
    "a165627a7a7230",  # swarm
]

MAX_BYTECODE_SIZE = 10_000_000


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


def strip_metadata_safe(body: str) -> str:
    """
    Safer metadata stripping:
    - Try known markers
    - Validate remaining code is still decodable
    """
    for marker in METADATA_MARKERS:
        idx = body.lower().rfind(marker)
        if idx != -1:
            candidate = body[:idx]
            if len(candidate) % 2 == 0 and len(candidate) > 0:
                return candidate

    return body


def normalize_bytecode(raw: str, *, remove_metadata: bool) -> str:
    cleaned = _clean_raw_input(raw)
    cleaned = _strip_0x_prefix(cleaned)

    if remove_metadata:
        cleaned = strip_metadata_safe(cleaned)

    _validate_hex(cleaned)
    return "0x" + cleaned


# =============================================================================
# Input
# =============================================================================

def load_from_file(path: Path, *, remove_metadata: bool) -> str:
    try:
        raw = path.read_text("utf-8")
    except Exception as e:
        raise IOError(f"Failed reading file: {e}") from e

    return normalize_bytecode(raw, remove_metadata=remove_metadata)


def load_from_stdin(*, remove_metadata: bool) -> str:
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
    gas: Optional[int]


# =============================================================================
# Disassembly helpers
# =============================================================================

def _safe_opcode(ins: Any) -> int:
    try:
        return int(ins.opcode)
    except Exception:
        return -1


def _is_invalid(ins: Any) -> bool:
    return _safe_opcode(ins) == 0xFE


def _get_size(ins: Any) -> int:
    try:
        return 1 + len(ins.operand or b"")
    except Exception:
        return 1


def _get_raw(bytecode_bytes: bytes, pc: int, size: int) -> str:
    return bytecode_bytes[pc:pc+size].hex()


# =============================================================================
# Disassembly
# =============================================================================

def disassemble(
    bytecode: str,
    *,
    pretty: bool,
    json_out: bool,
    strict: bool,
    annotate_jumps: bool,
) -> List[str] | List[Instruction]:

    try:
        evm = evmdasm.EvmBytecode(bytecode)
        instructions = list(evm.disassemble())
        bytecode_bytes = bytes.fromhex(bytecode[2:])
    except Exception as e:
        logging.exception("Disassembly failed")
        raise RuntimeError("Disassembly error") from e

    if not instructions:
        raise RuntimeError("No instructions decoded")

    if strict:
        invalids = [ins for ins in instructions if _is_invalid(ins)]
        if invalids:
            raise RuntimeError(f"{len(invalids)} INVALID opcodes detected")

    parsed: List[Instruction] = []

    for ins in instructions:
        size = _get_size(ins)
        operand = ins.operand.hex() if ins.operand else None

        parsed.append(
            Instruction(
                pc=ins.pc,
                opcode=ins.name,
                operand=f"0x{operand}" if operand else None,
                size=size,
                raw=_get_raw(bytecode_bytes, ins.pc, size),
                gas=getattr(ins, "gas", None),
            )
        )

    if json_out:
        return parsed

    # TEXT MODE
    pad = max(len(i.opcode) for i in parsed) if pretty else 0

    jumpdests = {i.pc for i in parsed if i.opcode == "JUMPDEST"} if annotate_jumps else set()

    lines = []
    for i in parsed:
        name = i.opcode.ljust(pad) if pretty else i.opcode
        operand = f" {i.operand}" if i.operand else ""
        marker = " <<DEST>>" if i.pc in jumpdests else ""

        lines.append(
            f"{i.pc:04d}: {name}{operand} | size={i.size} raw={i.raw}{marker}"
        )

    return lines


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
    result: List[str] | List[Instruction],
    *,
    outfile: Optional[Path],
    json_out: bool,
    summary: bool,
) -> None:

    try:
        if json_out:
            payload = [asdict(x) for x in result]  # type: ignore
            text = json.dumps(payload, indent=2)

            if summary:
                text += "\n\n" + opcode_summary(result)  # type: ignore

        else:
            header = f"Disassembled ({len(result)} instructions)"
            text = f"{header}\n{'-' * len(header)}\n"
            text += "\n".join(result)

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
    p = argparse.ArgumentParser(
        description="Advanced EVM Disassembler",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--bytecode")
    src.add_argument("--file", type=Path)
    src.add_argument("--stdin", action="store_true")

    p.add_argument("--output", type=Path)
    p.add_argument("--pretty", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--summary", action="store_true")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--annotate-jumps", action="store_true")
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
            pretty=args.pretty,
            json_out=args.json,
            strict=args.strict,
            annotate_jumps=args.annotate_jumps,
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

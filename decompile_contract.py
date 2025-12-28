#!/usr/bin/env python3
"""
Enhanced EVM Bytecode Disassembler
---------------------------------
A robust, defensive utility for disassembling Ethereum Virtual Machine (EVM)
bytecode using the `evmdasm` library.

Features:
  • Safe bytecode normalization and validation
  • Optional Solidity metadata stripping
  • Pretty or JSON output
  • Strict opcode validation
  • Opcode frequency summary
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

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

def setup_logging(level: int) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )


# =============================================================================
# Bytecode validation & normalization
# =============================================================================

HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]+$")

# Covers common Solidity metadata trailers (a264…, a165…, legacy variants)
METADATA_RE = re.compile(
    r"(a26[0-9a-f]{6,}|a165[0-9a-f]{6,})(?:00)?33[0-9a-f]*$",
    re.IGNORECASE,
)


def is_valid_hex(data: str) -> bool:
    return bool(HEX_RE.fullmatch(data))


def strip_metadata(hex_body: str) -> str:
    """Remove Solidity metadata suffix if present."""
    stripped = METADATA_RE.sub("", hex_body)
    return stripped or hex_body


def normalize_bytecode(raw: str, remove_metadata: bool) -> str:
    """
    Normalize raw bytecode into canonical 0x-prefixed lowercase hex.
    """
    # Remove comments first
    cleaned = re.sub(r"//.*?$", "", raw, flags=re.MULTILINE)
    cleaned = re.sub(r"\s+", "", cleaned).lower()

    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]

    if not cleaned:
        return ""

    if remove_metadata:
        cleaned = strip_metadata(cleaned)

    # EVM bytecode must be byte-aligned
    if len(cleaned) % 2 != 0:
        raise ValueError("Hex string has odd length")

    return "0x" + cleaned


# =============================================================================
# Input helpers
# =============================================================================

def load_from_file(path: Path, remove_metadata: bool) -> Optional[str]:
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as exc:
        logging.error("Failed to read '%s': %s", path, exc)
        return None

    try:
        return normalize_bytecode(raw, remove_metadata)
    except Exception as exc:
        logging.error("Invalid bytecode in '%s': %s", path, exc)
        return None


def load_from_stdin(remove_metadata: bool) -> Optional[str]:
    raw = sys.stdin.read()
    if not raw.strip():
        logging.error("No input received from stdin.")
        return None

    try:
        return normalize_bytecode(raw, remove_metadata)
    except Exception as exc:
        logging.error("Invalid bytecode from stdin: %s", exc)
        return None


# =============================================================================
# Disassembly
# =============================================================================

InstructionJSON = Dict[str, Any]
DisassemblyResult = Union[List[str], List[InstructionJSON]]


def disassemble(
    bytecode: str,
    *,
    pretty: bool,
    json_out: bool,
    strict: bool,
) -> DisassemblyResult:
    try:
        evm = evmdasm.EvmBytecode(bytecode)
        instructions = list(evm.disassemble())
    except Exception as exc:
        logging.exception("Disassembly failed: %s", exc)
        return []

    if not instructions:
        logging.error("No instructions decoded.")
        return []

    if strict:
        invalid = [
            ins for ins in instructions
            if ins.name.upper().startswith("INVALID")
        ]
        if invalid:
            logging.error(
                "Strict mode violation: %d INVALID opcodes found.",
                len(invalid),
            )
            return []

    if json_out:
        return [
            {
                "pc": ins.pc,
                "opcode": ins.name,
                "operand": ins.operand,
            }
            for ins in instructions
        ]

    max_op_len = max(len(ins.name) for ins in instructions) if pretty else 0
    lines: List[str] = []

    for ins in instructions:
        name = ins.name.ljust(max_op_len) if pretty else ins.name
        operand = f" {ins.operand}" if ins.operand else ""
        lines.append(f"{ins.pc:04d}: {name}{operand}")

    return lines


# =============================================================================
# Summary
# =============================================================================

def opcode_summary(data: Iterable[InstructionJSON]) -> str:
    counter = Counter(item["opcode"] for item in data)
    lines = ["Opcode Summary:"]
    for op, count in sorted(counter.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"  {op:<12} {count}")
    return "\n".join(lines)


# =============================================================================
# Output
# =============================================================================

def write_output(
    result: DisassemblyResult,
    *,
    outfile: Optional[Path],
    json_out: bool,
    summary: bool,
) -> int:
    if not result:
        return EXIT_DISASSEMBLY_ERROR

    if json_out:
        text = json.dumps(result, indent=2)
        if summary:
            text += "\n\n" + opcode_summary(result)  # type: ignore[arg-type]
    else:
        header = f"Disassembled EVM Instructions ({len(result)} ops)"
        text = f"{header}\n{'-' * len(header)}\n" + "\n".join(result)

    if outfile:
        try:
            outfile.write_text(text, encoding="utf-8")
            logging.info("Output written to '%s'.", outfile)
            return EXIT_SUCCESS
        except Exception as exc:
            logging.error("Write failed: %s", exc)
            return EXIT_WRITE_ERROR

    print(text)
    return EXIT_SUCCESS


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EVM Bytecode Disassembler",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--version", action="version", version="EVM Disassembler 2.2")

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--bytecode", help="Raw EVM bytecode")
    src.add_argument("--file", type=Path, help="File containing bytecode")
    src.add_argument("--stdin", action="store_true", help="Read bytecode from stdin")

    parser.add_argument("--output", type=Path, help="Write output to file")
    parser.add_argument("--pretty", action="store_true", help="Aligned output")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--summary", action="store_true", help="Opcode summary")
    parser.add_argument("--strict", action="store_true", help="Fail on INVALID opcodes")
    parser.add_argument("--no-metadata", action="store_true", help="Keep Solidity metadata")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    return parser.parse_args()


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    args = parse_args()
    setup_logging(logging.DEBUG if args.debug else logging.INFO)

    remove_metadata = not args.no_metadata

    try:
        if args.bytecode:
            bytecode = normalize_bytecode(args.bytecode, remove_metadata)
        elif args.file:
            bytecode = load_from_file(args.file, remove_metadata)
        else:
            bytecode = load_from_stdin(remove_metadata)
    except ValueError as exc:
        logging.error("Bytecode error: %s", exc)
        return EXIT_INVALID_BYTECODE

    if not bytecode or not is_valid_hex(bytecode):
        logging.error("Invalid EVM bytecode.")
        return EXIT_INVALID_BYTECODE

    result = disassemble(
        bytecode,
        pretty=args.pretty,
        json_out=args.json,
        strict=args.strict,
    )

    return write_output(
        result,
        outfile=args.output,
        json_out=args.json,
        summary=args.summary,
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)

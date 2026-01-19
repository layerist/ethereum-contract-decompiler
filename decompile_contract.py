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

def setup_logging(debug: bool) -> None:
    """Configure application-wide logging."""
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
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


def is_valid_hex(value: str) -> bool:
    """Return True if the value is a valid hex string (optionally 0x-prefixed)."""
    return bool(HEX_RE.fullmatch(value))


def strip_metadata(hex_body: str) -> str:
    """
    Remove Solidity compiler metadata if present.
    If stripping would result in empty bytecode, return original input.
    """
    stripped = METADATA_RE.sub("", hex_body)
    return stripped if stripped else hex_body


def normalize_bytecode(raw: str, *, remove_metadata: bool) -> str:
    """
    Normalize raw input into canonical, lowercase, 0x-prefixed bytecode.
    """
    # Remove comments and whitespace
    cleaned = re.sub(r"//.*?$", "", raw, flags=re.MULTILINE)
    cleaned = re.sub(r"\s+", "", cleaned).lower()

    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]

    if not cleaned:
        raise ValueError("Empty bytecode")

    if remove_metadata:
        cleaned = strip_metadata(cleaned)

    if len(cleaned) % 2 != 0:
        raise ValueError("Hex string length must be even")

    return f"0x{cleaned}"


# =============================================================================
# Input helpers
# =============================================================================

def load_from_file(path: Path, *, remove_metadata: bool) -> str:
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as exc:
        raise IOError(f"Failed to read file '{path}': {exc}") from exc

    return normalize_bytecode(raw, remove_metadata=remove_metadata)


def load_from_stdin(*, remove_metadata: bool) -> str:
    raw = sys.stdin.read()
    if not raw.strip():
        raise ValueError("No input received from stdin")

    return normalize_bytecode(raw, remove_metadata=remove_metadata)


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
    """Disassemble EVM bytecode into instructions."""
    try:
        evm = evmdasm.EvmBytecode(bytecode)
        instructions = list(evm.disassemble())
    except Exception as exc:
        logging.exception("Disassembly failed")
        raise RuntimeError("EVM disassembly error") from exc

    if not instructions:
        raise RuntimeError("No instructions decoded")

    if strict:
        invalid_ops = [
            ins for ins in instructions
            if ins.name.upper().startswith("INVALID")
        ]
        if invalid_ops:
            raise RuntimeError(
                f"Strict mode violation: {len(invalid_ops)} INVALID opcode(s) found"
            )

    if json_out:
        return [
            {
                "pc": ins.pc,
                "opcode": ins.name,
                "operand": ins.operand,
            }
            for ins in instructions
        ]

    pad = max(len(ins.name) for ins in instructions) if pretty else 0
    return [
        f"{ins.pc:04d}: {ins.name.ljust(pad) if pretty else ins.name}"
        f"{f' {ins.operand}' if ins.operand else ''}"
        for ins in instructions
    ]


# =============================================================================
# Summary
# =============================================================================

def opcode_summary(data: Iterable[InstructionJSON]) -> str:
    """Generate opcode frequency summary."""
    counter = Counter(item["opcode"] for item in data)
    lines = ["Opcode Summary:"]
    for opcode, count in sorted(counter.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"  {opcode:<12} {count}")
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
) -> None:
    """Write or print the final output."""
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
            logging.info("Output written to '%s'", outfile)
        except Exception as exc:
            raise IOError(f"Failed to write output: {exc}") from exc
    else:
        print(text)


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EVM Bytecode Disassembler",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--version", action="version", version="EVM Disassembler 2.3")

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--bytecode", help="Raw EVM bytecode")
    src.add_argument("--file", type=Path, help="File containing bytecode")
    src.add_argument("--stdin", action="store_true", help="Read bytecode from stdin")

    parser.add_argument("--output", type=Path, help="Write output to file")
    parser.add_argument("--pretty", action="store_true", help="Align opcodes")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--summary", action="store_true", help="Opcode summary")
    parser.add_argument("--strict", action="store_true", help="Fail on INVALID opcodes")
    parser.add_argument("--no-metadata", action="store_true", help="Preserve Solidity metadata")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

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

        if not is_valid_hex(bytecode):
            raise ValueError("Invalid hex bytecode")

        result = disassemble(
            bytecode,
            pretty=args.pretty,
            json_out=args.json,
            strict=args.strict,
        )

        write_output(
            result,
            outfile=args.output,
            json_out=args.json,
            summary=args.summary,
        )

        return EXIT_SUCCESS

    except ValueError as exc:
        logging.error("Invalid bytecode: %s", exc)
        return EXIT_INVALID_BYTECODE

    except IOError as exc:
        logging.error("%s", exc)
        return EXIT_READ_ERROR

    except RuntimeError as exc:
        logging.error("%s", exc)
        return EXIT_DISASSEMBLY_ERROR


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)

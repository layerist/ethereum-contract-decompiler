#!/usr/bin/env python3
"""
Enhanced EVM Bytecode Disassembler (Hardened Edition)
-----------------------------------------------------

A robust, defensive utility for disassembling Ethereum Virtual Machine (EVM)
bytecode using the `evmdasm` library.

Enhancements over base version:
  • Stronger validation and normalization
  • Accurate INVALID opcode detection (byte-level)
  • Safer metadata stripping
  • Deterministic formatting
  • Strict error classification
  • Clean separation of JSON vs text pipelines
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

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
# Constants & Regex
# =============================================================================

HEX_RE = re.compile(r"^[0-9a-f]+$")
COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)

# Common Solidity metadata prefixes (modern + legacy)
METADATA_RE = re.compile(
    r"(a2646970667358|a165627a7a7230)[0-9a-f]*$",
    re.IGNORECASE,
)

MAX_BYTECODE_SIZE = 10_000_000  # 10 MB safety cap


# =============================================================================
# Utilities
# =============================================================================

def _clean_raw_input(raw: str) -> str:
    raw = COMMENT_RE.sub("", raw)
    raw = re.sub(r"\s+", "", raw)
    return raw.lower()


def _strip_0x_prefix(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def _validate_hex_body(body: str) -> None:
    if not body:
        raise ValueError("Bytecode is empty")

    if len(body) % 2 != 0:
        raise ValueError("Hex string length must be even")

    if not HEX_RE.fullmatch(body):
        raise ValueError("Non-hex characters detected")

    if len(body) // 2 > MAX_BYTECODE_SIZE:
        raise ValueError("Bytecode exceeds maximum allowed size")


def strip_metadata(body: str) -> str:
    stripped = METADATA_RE.sub("", body)
    return stripped if stripped else body


def normalize_bytecode(raw: str, *, remove_metadata: bool) -> str:
    cleaned = _clean_raw_input(raw)
    cleaned = _strip_0x_prefix(cleaned)

    if remove_metadata:
        cleaned = strip_metadata(cleaned)

    _validate_hex_body(cleaned)

    return f"0x{cleaned}"


# =============================================================================
# Input loaders
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

@dataclass(frozen=True)
class InstructionJSON:
    pc: int
    opcode: str
    operand: Optional[str]


def _is_invalid_opcode(ins: Any) -> bool:
    """
    Reliable INVALID detection:
    INVALID opcode in EVM is 0xfe.
    """
    try:
        return ins.opcode == 0xFE
    except Exception:
        return ins.name.upper().startswith("INVALID")


def disassemble(
    bytecode: str,
    *,
    pretty: bool,
    json_out: bool,
    strict: bool,
) -> List[str] | List[InstructionJSON]:

    try:
        evm = evmdasm.EvmBytecode(bytecode)
        instructions = list(evm.disassemble())
    except Exception as exc:
        logging.exception("Disassembly failure")
        raise RuntimeError("EVM disassembly error") from exc

    if not instructions:
        raise RuntimeError("No instructions decoded")

    if strict:
        invalid = [ins for ins in instructions if _is_invalid_opcode(ins)]
        if invalid:
            raise RuntimeError(
                f"Strict mode violation: {len(invalid)} INVALID opcode(s) found"
            )

    if json_out:
        return [
            InstructionJSON(
                pc=ins.pc,
                opcode=ins.name,
                operand=f"0x{ins.operand.hex()}" if ins.operand else None,
            )
            for ins in instructions
        ]

    # Text mode
    pad = max(len(ins.name) for ins in instructions) if pretty else 0

    lines = []
    for ins in instructions:
        operand = (
            f" 0x{ins.operand.hex()}" if ins.operand else ""
        )
        name = ins.name.ljust(pad) if pretty else ins.name
        lines.append(f"{ins.pc:04d}: {name}{operand}")

    return lines


# =============================================================================
# Summary
# =============================================================================

def opcode_summary(data: Iterable[InstructionJSON]) -> str:
    counter = Counter(item.opcode for item in data)
    lines = ["Opcode Summary:"]
    for opcode, count in sorted(counter.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"  {opcode:<16} {count}")
    return "\n".join(lines)


# =============================================================================
# Output
# =============================================================================

def write_output(
    result: List[str] | List[InstructionJSON],
    *,
    outfile: Optional[Path],
    json_out: bool,
    summary: bool,
) -> None:

    try:
        if json_out:
            json_payload = [
                vars(item) for item in result  # dataclass → dict
            ]
            text = json.dumps(json_payload, indent=2)

            if summary:
                text += "\n\n" + opcode_summary(result)  # type: ignore

        else:
            header = f"Disassembled EVM Instructions ({len(result)} ops)"
            text = f"{header}\n{'-' * len(header)}\n"
            text += "\n".join(result)

        if outfile:
            outfile.write_text(text, encoding="utf-8")
            logging.info("Output written to '%s'", outfile)
        else:
            print(text)

    except Exception as exc:
        raise IOError(f"Failed to write output: {exc}") from exc


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EVM Bytecode Disassembler",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="EVM Disassembler 3.0",
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--bytecode", help="Raw EVM bytecode")
    src.add_argument("--file", type=Path, help="File containing bytecode")
    src.add_argument("--stdin", action="store_true", help="Read bytecode from stdin")

    parser.add_argument("--output", type=Path, help="Write output to file")
    parser.add_argument("--pretty", action="store_true", help="Align opcodes")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--summary", action="store_true", help="Opcode frequency summary")
    parser.add_argument("--strict", action="store_true", help="Fail on INVALID opcodes")
    parser.add_argument(
        "--no-metadata",
        action="store_true",
        help="Do NOT strip Solidity compiler metadata",
    )
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

    except Exception:
        logging.exception("Unexpected fatal error")
        return EXIT_WRITE_ERROR


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)

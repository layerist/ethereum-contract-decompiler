#!/usr/bin/env python3
"""
Enhanced EVM Bytecode Disassembler (Improved)
----------------------------------------------
A safer, cleaner, and more feature-complete utility for disassembling Ethereum
Virtual Machine (EVM) bytecode using the `evmdasm` library.

New improvements:
    • Improved metadata stripping.
    • Consistent error handling.
    • More defensive bytecode parsing.
    • Optional metadata stripping (--no-metadata).
    • Clearer structure and naming.
    • Stronger pretty-printing alignment.
    • Enhanced strict mode checking.
"""

import argparse
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional, Union, Dict, Any

import evmdasm


# Exit codes
EXIT_SUCCESS = 0
EXIT_INVALID_BYTECODE = 2
EXIT_READ_ERROR = 3
EXIT_DISASSEMBLY_ERROR = 4
EXIT_WRITE_ERROR = 5


# ---------------------------------------------------------------------------- #
# Logging
# ---------------------------------------------------------------------------- #

def setup_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S"
    )


# ---------------------------------------------------------------------------- #
# Bytecode validation & normalization
# ---------------------------------------------------------------------------- #

HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]+$", re.IGNORECASE)

# Solidity metadata patterns (many variations)
# This covers a264..., a165..., and generic older formats.
METADATA_RE = re.compile(
    r"(a26[0-9a-f]{6,}|a165[0-9a-f]{6,})(?:00)?33[0-9a-f]*$",
    re.IGNORECASE
)


def is_valid_bytecode(data: str) -> bool:
    return bool(HEX_RE.fullmatch(data.strip()))


def strip_metadata(bytecode: str) -> str:
    """Remove Solidity metadata trailer (several known patterns)."""
    cleaned = METADATA_RE.sub("", bytecode)
    return cleaned if cleaned else bytecode


def normalize_bytecode(bytecode: str, remove_metadata: bool = True) -> str:
    bc = bytecode.strip().lower()
    if bc.startswith("0x"):
        bc = bc[2:]

    bc = re.sub(r"\s+", "", bc)
    bc = re.sub(r"//.*?$", "", bc)

    if remove_metadata:
        bc = strip_metadata(bc)

    return "0x" + bc


# ---------------------------------------------------------------------------- #
# Input helpers
# ---------------------------------------------------------------------------- #

def load_bytecode_from_file(path: Path, remove_metadata: bool) -> Optional[str]:
    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        logging.error("Failed to read file '%s': %s", path, e)
        return None

    content = content.strip().replace("\n", "").replace(" ", "")
    if not content:
        logging.error("File '%s' is empty.", path)
        return None

    if not is_valid_bytecode(content):
        logging.error("File '%s' does not contain valid bytecode.", path)
        return None

    return normalize_bytecode(content, remove_metadata)


def read_from_stdin(remove_metadata: bool) -> Optional[str]:
    data = sys.stdin.read()
    if not data.strip():
        logging.error("No bytecode received from stdin.")
        return None

    parts = re.split(r"\s+", data)
    valid = [normalize_bytecode(p, remove_metadata) for p in parts if is_valid_bytecode(p)]

    if len(valid) != 1:
        logging.error("Stdin must contain exactly one bytecode sequence.")
        return None

    return valid[0]


# ---------------------------------------------------------------------------- #
# Disassembly
# ---------------------------------------------------------------------------- #

def disassemble_bytecode(
    bytecode: str,
    pretty: bool = False,
    json_out: bool = False,
    strict: bool = False
) -> Union[List[str], List[Dict[str, Any]]]:

    try:
        evm = evmdasm.EvmBytecode(bytecode)
        instructions = evm.disassemble()
    except Exception as e:
        logging.exception("evmdasm failed to disassemble bytecode: %s", e)
        return []

    if not instructions:
        logging.error("No instructions decoded.")
        return []

    # Strict mode: reject INVALID opcodes
    if strict:
        invalids = [i for i in instructions if i.name.upper().startswith("INVALID")]
        if invalids:
            logging.error("Strict mode error: %d invalid opcodes detected.", len(invalids))
            return []

    if json_out:
        return [
            {
                "pc": instr.pc,
                "name": instr.name,
                "operand": instr.operand or None
            }
            for instr in instructions
        ]

    # Pretty printing: align columns
    if pretty:
        max_opcode = max(len(i.name) for i in instructions)
    else:
        max_opcode = 0

    result: List[str] = []
    for instr in instructions:
        name = instr.name.ljust(max_opcode) if pretty else instr.name
        operand = instr.operand or ""
        result.append(f"{instr.pc:04d}: {name} {operand}".rstrip())

    return result


# ---------------------------------------------------------------------------- #
# Summary generation
# ---------------------------------------------------------------------------- #

def summarize(instructions: List[Dict[str, Any]]) -> str:
    counts = Counter(i["name"] for i in instructions)
    ops = sorted(counts.items(), key=lambda x: (-x[1], x[0]))

    lines = ["Opcode Summary:"]
    for op, count in ops:
        lines.append(f"  {op:<12} {count}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------- #
# Output handling
# ---------------------------------------------------------------------------- #

def output_result(
    data: Union[List[str], List[Dict[str, Any]]],
    outfile: Optional[Path],
    json_out: bool,
    summary_flag: bool
) -> int:

    if not data:
        return EXIT_DISASSEMBLY_ERROR

    if json_out:
        text = json.dumps(data, indent=2)
        if summary_flag and isinstance(data[0], dict):
            text += "\n\n" + summarize(data)
    else:
        header = f"Disassembled EVM Instructions ({len(data)} ops)"
        body = "\n".join(data)
        text = f"{header}\n{'-' * len(header)}\n{body}"

    if outfile:
        try:
            outfile.write_text(text, encoding="utf-8")
            logging.info("Output written to '%s'.", outfile)
            return EXIT_SUCCESS
        except Exception as e:
            logging.error("Failed to write to '%s': %s", outfile, e)
            return EXIT_WRITE_ERROR

    print(text)
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------- #
# CLI
# ---------------------------------------------------------------------------- #

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EVM Bytecode Disassembler",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("--version", action="version", version="EVM Disassembler 2.1")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bytecode", type=str, help="Raw EVM bytecode")
    group.add_argument("--file", type=Path, help="Text file with bytecode")
    group.add_argument("--stdin", action="store_true", help="Read bytecode from stdin")

    parser.add_argument("--output", type=Path, help="Write output to a file")
    parser.add_argument("--pretty", action="store_true", help="Aligned output")
    parser.add_argument("--json", action="store_true", help="JSON output format")
    parser.add_argument("--summary", action="store_true", help="Include opcode summary")
    parser.add_argument("--strict", action="store_true", help="Fail on INVALID opcodes")
    parser.add_argument("--no-metadata", action="store_true", help="Do NOT strip metadata")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    return parser.parse_args()


# ---------------------------------------------------------------------------- #
# Runner
# ---------------------------------------------------------------------------- #

def main() -> int:
    args = parse_args()
    setup_logging(logging.DEBUG if args.debug else logging.INFO)

    remove_metadata = not args.no_metadata

    if args.bytecode:
        bc = normalize_bytecode(args.bytecode, remove_metadata)
    elif args.file:
        bc = load_bytecode_from_file(args.file, remove_metadata)
    else:
        bc = read_from_stdin(remove_metadata)

    if not bc:
        return EXIT_READ_ERROR

    if not is_valid_bytecode(bc):
        logging.error("Invalid bytecode input.")
        return EXIT_INVALID_BYTECODE

    instructions = disassemble_bytecode(
        bc,
        pretty=args.pretty,
        json_out=args.json,
        strict=args.strict
    )

    return output_result(
        instructions,
        outfile=args.output,
        json_out=args.json,
        summary_flag=args.summary
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)

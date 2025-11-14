#!/usr/bin/env python3
"""
Enhanced EVM Bytecode Disassembler
-----------------------------------
A safer, cleaner, and more feature-complete utility for disassembling Ethereum
Virtual Machine (EVM) bytecode using the `evmdasm` library.

Features:
    • Read bytecode from argument, file, or stdin.
    • Pretty / aligned output.
    • JSON output mode.
    • Opcode usage summary.
    • Metadata auto-stripping.
    • Strict mode for opcode validation.

Usage:
    python disassembler.py --bytecode 0x6001600101
    python disassembler.py --file bytecode.txt --output result.txt
    cat bytecode.txt | python disassembler.py --stdin --pretty
"""

import argparse
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional, Union

import evmdasm

# Exit codes
EXIT_SUCCESS = 0
EXIT_INVALID_BYTECODE = 2
EXIT_READ_ERROR = 3
EXIT_DISASSEMBLY_ERROR = 4
EXIT_WRITE_ERROR = 5


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def setup_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #

BYTECODE_REGEX = re.compile(r"^(0x)?[0-9a-fA-F]+$", re.IGNORECASE)


def is_valid_bytecode(data: str) -> bool:
    return bool(BYTECODE_REGEX.fullmatch(data.strip()))


def strip_metadata(bytecode: str) -> str:
    """
    Remove Solidity compiler metadata trailer if present.
    Metadata typically starts with `a264` or `a165` and ends with `0033`.
    """
    cleaned = re.sub(r"(a26[0-9a-f]{6,})0033.*$", "", bytecode, flags=re.IGNORECASE)
    return cleaned or bytecode


def normalize_bytecode(bytecode: str) -> str:
    bc = bytecode.strip().lower()
    bc = bc[2:] if bc.startswith("0x") else bc
    bc = strip_metadata(bc)
    return "0x" + bc


# --------------------------------------------------------------------------- #
# I/O helpers
# --------------------------------------------------------------------------- #

def load_bytecode_from_file(path: Path) -> Optional[str]:
    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        logging.error("Failed to read file %s: %s", path, e)
        return None

    content = re.sub(r"\s+", "", content)
    if not content:
        logging.error("File is empty: %s", path)
        return None

    if not is_valid_bytecode(content):
        logging.error("Invalid bytecode format in file: %s", path)
        return None

    return normalize_bytecode(content)


def read_from_stdin() -> Optional[str]:
    data = sys.stdin.read().strip()
    if not data:
        logging.error("No bytecode received via stdin.")
        return None

    parts = re.split(r"\s+", data)
    valid = [normalize_bytecode(p) for p in parts if is_valid_bytecode(p)]

    if len(valid) == 1:
        return valid[0]

    logging.error("Provide exactly one bytecode sequence to stdin.")
    return None


# --------------------------------------------------------------------------- #
# Disassembly
# --------------------------------------------------------------------------- #

def disassemble_bytecode(
    bytecode: str,
    pretty: bool = False,
    json_out: bool = False,
    strict: bool = False
) -> Union[List[str], List[dict]]:
    try:
        evm = evmdasm.EvmBytecode(bytecode)
        instructions = evm.disassemble()

        if not instructions:
            logging.warning("No EVM instructions decoded.")
            return []

        if strict:
            unknown = [instr for instr in instructions if instr.name.startswith("INVALID")]
            if unknown:
                logging.error("Strict mode: unknown opcodes detected.")
                return []

        if json_out:
            return [
                {
                    "pc": instr.pc,
                    "name": instr.name,
                    "operand": instr.operand,
                }
                for instr in instructions
            ]

        max_len = max(len(i.name) for i in instructions) if pretty else 0

        output = []
        for instr in instructions:
            name = instr.name.ljust(max_len) if pretty else instr.name
            operand = instr.operand or ""
            output.append(f"{instr.pc:04d}: {name} {operand}".rstrip())

        return output

    except Exception as e:
        logging.exception("Disassembly error: %s", e)
        return []


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def summarize(instructions: List[dict]) -> str:
    counts = Counter(i["name"] for i in instructions)
    sorted_ops = sorted(counts.items(), key=lambda x: (-x[1], x[0]))

    lines = ["Opcode Summary:"]
    lines.extend(f"  {op:<12} {count}" for op, count in sorted_ops)
    return "\n".join(lines)


def output_result(
    instructions: Union[List[str], List[dict]],
    outfile: Optional[Path],
    json_out: bool,
    summary_flag: bool
) -> int:
    if not instructions:
        logging.error("No instructions to output.")
        return EXIT_DISASSEMBLY_ERROR

    if json_out:
        text = json.dumps(instructions, indent=2)
        if summary_flag and isinstance(instructions[0], dict):
            text += "\n\n" + summarize(instructions)
    else:
        header = f"Disassembled EVM Instructions ({len(instructions)} ops)"
        body = "\n".join(instructions)
        text = f"{header}\n{'-' * len(header)}\n{body}"

    if outfile:
        try:
            outfile.write_text(text, encoding="utf-8")
            logging.info("Written to: %s", outfile)
            return EXIT_SUCCESS
        except Exception as e:
            logging.error("Failed to write file %s: %s", outfile, e)
            return EXIT_WRITE_ERROR

    print(text)
    return EXIT_SUCCESS


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

def run(
    bytecode: str,
    outfile: Optional[Path],
    pretty: bool,
    json_out: bool,
    summary: bool,
    strict: bool
) -> int:

    if not is_valid_bytecode(bytecode):
        logging.error("Invalid bytecode input.")
        return EXIT_INVALID_BYTECODE

    bc = normalize_bytecode(bytecode)
    instructions = disassemble_bytecode(bc, pretty, json_out, strict)

    if not instructions:
        return EXIT_DISASSEMBLY_ERROR

    return output_result(instructions, outfile, json_out, summary)


# --------------------------------------------------------------------------- #
# CLI parser
# --------------------------------------------------------------------------- #

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Disassemble Ethereum Virtual Machine bytecode.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--version", action="version", version="EVM Disassembler 2.0")

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--bytecode", type=str, help="Raw EVM bytecode")
    src.add_argument("--file", type=Path, help="File containing EVM bytecode")
    src.add_argument("--stdin", action="store_true", help="Read bytecode from stdin")

    parser.add_argument("--output", type=Path, help="Save output to file")
    parser.add_argument("--pretty", action="store_true", help="Aligned output")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--summary", action="store_true", help="Include opcode summary")
    parser.add_argument("--strict", action="store_true", help="Fail on unknown opcodes")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    return parser.parse_args()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> int:
    args = parse_args()
    setup_logging(logging.DEBUG if args.debug else logging.INFO)

    if args.bytecode:
        bc = args.bytecode
    elif args.file:
        bc = load_bytecode_from_file(args.file)
    else:  # stdin
        bc = read_from_stdin()

    if not bc:
        return EXIT_READ_ERROR

    return run(
        bc,
        args.output,
        args.pretty,
        args.json,
        args.summary,
        args.strict
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)

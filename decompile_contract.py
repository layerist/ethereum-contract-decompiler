#!/usr/bin/env python3
"""
EVM Bytecode Disassembler
--------------------------
Disassembles Ethereum Virtual Machine (EVM) bytecode into human-readable instructions.
Supports input via raw bytecode, file, or stdin.

Usage examples:
    python disassembler.py --bytecode 0x6001600101
    python disassembler.py --file bytecode.txt --output output.txt
    cat bytecode.txt | python disassembler.py --stdin
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import List, Optional

import evmdasm

# Exit codes
EXIT_SUCCESS = 0
EXIT_INVALID_BYTECODE = 2
EXIT_READ_ERROR = 3
EXIT_DISASSEMBLY_ERROR = 4
EXIT_WRITE_ERROR = 5


def setup_logging(level: int = logging.INFO) -> None:
    """Configure logging format and level."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
    )


def is_valid_bytecode(bytecode: str) -> bool:
    """Return True if the string looks like valid EVM bytecode (with or without 0x)."""
    return bool(re.fullmatch(r"(0x)?[0-9a-fA-F]+", bytecode))


def normalize_bytecode(bytecode: str) -> str:
    """Ensure bytecode has a 0x prefix and no whitespace."""
    bc = bytecode.strip().lower()
    return bc if bc.startswith("0x") else "0x" + bc


def load_bytecode_from_file(file_path: Path) -> Optional[str]:
    """
    Load and validate EVM bytecode from a file.
    Returns the bytecode string if valid, otherwise None.
    """
    try:
        content = file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logging.error("File not found: %s", file_path)
        return None
    except OSError as e:
        logging.error("Could not read file %s: %s", file_path, e)
        return None

    content = re.sub(r"\s+", "", content)  # remove whitespace
    if not content:
        logging.error("File is empty: %s", file_path)
        return None

    if not is_valid_bytecode(content):
        logging.error("Invalid bytecode format in file: %s", file_path)
        return None

    return normalize_bytecode(content)


def disassemble_bytecode(bytecode: str, pretty: bool = False, json_out: bool = False) -> List[str]:
    """Disassemble EVM bytecode into human-readable instructions."""
    try:
        instructions = evmdasm.EvmBytecode(bytecode).disassemble()
        if not instructions:
            logging.warning("No instructions found in bytecode.")
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

        if pretty:
            max_len = max(len(instr.name) for instr in instructions)
            return [
                f"{instr.pc:04d}: {instr.name.ljust(max_len)} {instr.operand or ''}".rstrip()
                for instr in instructions
            ]

        return [str(instr) for instr in instructions]

    except Exception as e:
        logging.exception("Failed to disassemble bytecode: %s", e)
        return []


def output_instructions(instructions, output_file: Optional[Path], json_out: bool) -> int:
    """Print or write disassembled instructions."""
    if not instructions:
        logging.warning("No instructions to output.")
        return EXIT_DISASSEMBLY_ERROR

    if json_out:
        output_data = json.dumps(instructions, indent=2)
    else:
        header = f"Disassembled EVM Instructions ({len(instructions)} ops):"
        output_data = "\n".join(
            [header, "-" * len(header), *instructions]
        )

    if output_file:
        try:
            output_file.write_text(output_data, encoding="utf-8")
            logging.info("Instructions written to: %s", output_file)
        except OSError as e:
            logging.error("Failed to write to file %s: %s", output_file, e)
            return EXIT_WRITE_ERROR
    else:
        print(output_data)

    return EXIT_SUCCESS


def run_disassembler(bytecode: str, output_file: Optional[Path], pretty: bool, json_out: bool) -> int:
    """Validate, disassemble, and output bytecode. Returns an exit code."""
    if not is_valid_bytecode(bytecode):
        logging.error("Invalid bytecode. Must contain only hex characters, optional '0x' prefix.")
        return EXIT_INVALID_BYTECODE

    bytecode = normalize_bytecode(bytecode)
    instructions = disassemble_bytecode(bytecode, pretty=pretty, json_out=json_out)
    if not instructions:
        return EXIT_DISASSEMBLY_ERROR

    return output_instructions(instructions, output_file, json_out)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="EVM Bytecode Disassembler")
    parser.add_argument("--version", action="version", version="EVM Disassembler 1.2")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--bytecode", type=str, help="Raw EVM bytecode string")
    group.add_argument("--file", type=Path, help="Path to a file containing EVM bytecode")
    group.add_argument("--stdin", action="store_true", help="Read EVM bytecode from stdin")

    parser.add_argument("--output", type=Path, help="Output file for disassembled instructions")
    parser.add_argument("--debug", action="store_true", help="Enable debug-level logging")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print disassembly with aligned output")
    parser.add_argument("--json", action="store_true", help="Output instructions in JSON format")

    return parser.parse_args()


def read_from_stdin() -> Optional[str]:
    """Read and validate bytecode from stdin."""
    stdin_data = sys.stdin.read().strip()
    if not stdin_data:
        return None

    parts = re.split(r"\s+", stdin_data)
    valid_parts = [normalize_bytecode(p) for p in parts if is_valid_bytecode(p)]

    if len(valid_parts) == 1:
        return valid_parts[0]

    if len(valid_parts) > 1:
        logging.error("Multiple bytecode sequences provided via stdin. Use one at a time.")
        return None

    return None


def main() -> int:
    """Main entry point. Returns exit code."""
    args = parse_args()
    setup_logging(logging.DEBUG if args.debug else logging.INFO)

    bytecode: Optional[str] = None

    if args.bytecode:
        bytecode = args.bytecode
    elif args.file:
        bytecode = load_bytecode_from_file(args.file)
    elif args.stdin:
        bytecode = read_from_stdin()

    if not bytecode:
        logging.error("No valid bytecode provided.")
        return EXIT_READ_ERROR

    return run_disassembler(bytecode, args.output, args.pretty, args.json)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
EVM Bytecode Disassembler
--------------------------
Disassembles Ethereum Virtual Machine (EVM) bytecode into human-readable instructions.
Supports input via raw bytecode, file, or stdin.

Usage examples:
    python disassembler.py --bytecode 0x6001600101
    python disassembler.py --file bytecode.txt --output output.txt
    cat bytecode.txt | python disassembler.py
"""

import argparse
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


def setup_logging(level: int = logging.INFO) -> None:
    """Configure logging format and level."""
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")


def is_valid_bytecode(bytecode: str) -> bool:
    """Return True if the string looks like valid EVM bytecode."""
    return bool(re.fullmatch(r"0x[0-9a-fA-F]+", bytecode))


def load_bytecode_from_file(file_path: Path) -> Optional[str]:
    """
    Load and validate EVM bytecode from a file.
    Returns the bytecode string if valid, otherwise None.
    """
    try:
        content = file_path.read_text(encoding="utf-8")
        # Normalize whitespace, join lines
        content = re.sub(r"\s+", "", content)
        if not content:
            logging.error("File is empty: %s", file_path)
            return None
        if not is_valid_bytecode(content):
            logging.error("Invalid bytecode format in file: %s", file_path)
            return None
        return content
    except FileNotFoundError:
        logging.error("File not found: %s", file_path)
    except OSError as e:
        logging.error("Could not read file %s: %s", file_path, e)
    return None


def disassemble_bytecode(bytecode: str, pretty: bool = False) -> List[str]:
    """Disassemble EVM bytecode into human-readable instructions."""
    try:
        instructions = evmdasm.EvmBytecode(bytecode).disassemble()
        if pretty:
            # Align opcodes for nicer output
            max_len = max(len(instr.name) for instr in instructions) if instructions else 0
            return [f"{instr.pc:04d}: {instr.name.ljust(max_len)} {instr.operand or ''}".rstrip()
                    for instr in instructions]
        return [str(instr) for instr in instructions]
    except Exception as e:
        logging.exception("Failed to disassemble bytecode: %s", e)
        return []


def output_instructions(instructions: List[str], output_file: Optional[Path]) -> None:
    """Print or write disassembled instructions."""
    if not instructions:
        logging.warning("No instructions to output.")
        return

    if output_file:
        try:
            output_file.write_text("\n".join(instructions), encoding="utf-8")
            logging.info("Instructions written to: %s", output_file)
        except OSError as e:
            logging.error("Failed to write to file %s: %s", output_file, e)
    else:
        print("\nDisassembled EVM Instructions:\n")
        for instr in instructions:
            print(instr)


def run_disassembler(bytecode: str, output_file: Optional[Path], pretty: bool) -> int:
    """
    Validate, disassemble, and output bytecode.
    Returns an exit code.
    """
    if not is_valid_bytecode(bytecode):
        logging.error("Invalid bytecode. Must start with '0x' and contain only hex characters.")
        return EXIT_INVALID_BYTECODE

    instructions = disassemble_bytecode(bytecode, pretty=pretty)
    if not instructions:
        return EXIT_DISASSEMBLY_ERROR

    output_instructions(instructions, output_file)
    return EXIT_SUCCESS


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="EVM Bytecode Disassembler")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--bytecode", type=str, help="Raw EVM bytecode string (must start with 0x)")
    group.add_argument("--file", type=Path, help="Path to a file containing EVM bytecode")

    parser.add_argument("--output", type=Path, help="Output file for disassembled instructions")
    parser.add_argument("--debug", action="store_true", help="Enable debug-level logging")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print disassembly with aligned output")

    return parser.parse_args()


def main() -> int:
    """Main entry point. Returns exit code."""
    args = parse_args()
    setup_logging(logging.DEBUG if args.debug else logging.INFO)

    bytecode: Optional[str] = args.bytecode

    if args.file:
        bytecode = load_bytecode_from_file(args.file)

    # If neither argument was provided, try reading from stdin
    if not bytecode:
        stdin_data = sys.stdin.read().strip() if not sys.stdin.isatty() else ""
        if stdin_data and is_valid_bytecode(stdin_data):
            bytecode = stdin_data

    if not bytecode:
        logging.error("No valid bytecode provided.")
        return EXIT_READ_ERROR

    return run_disassembler(bytecode, args.output, args.pretty)


if __name__ == "__main__":
    sys.exit(main())

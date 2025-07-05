#!/usr/bin/env python3

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


def setup_logging(level: int = logging.INFO) -> None:
    """
    Configure the logging format and level.
    """
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


def is_valid_bytecode(bytecode: str) -> bool:
    """
    Check if the provided string is valid EVM bytecode:
    it must start with '0x' and be valid hexadecimal.
    """
    return re.fullmatch(r"0x[0-9a-fA-F]+", bytecode) is not None


def load_bytecode_from_file(file_path: Path) -> Optional[str]:
    """
    Load and validate EVM bytecode from a given file path.
    Returns the bytecode string if valid, otherwise None.
    """
    try:
        content = file_path.read_text(encoding="utf-8").strip()
        if not content:
            logging.error("The file is empty: %s", file_path)
            return None
        if not is_valid_bytecode(content):
            logging.error("Invalid bytecode format in file: %s", file_path)
            return None
        logging.debug("Successfully loaded bytecode from: %s", file_path)
        return content
    except FileNotFoundError:
        logging.error("File not found: %s", file_path)
    except OSError as e:
        logging.error("Could not read file %s: %s", file_path, e)
    return None


def disassemble_bytecode(bytecode: str) -> List[str]:
    """
    Disassemble EVM bytecode to a list of human-readable instructions.
    """
    try:
        logging.debug("Starting disassembly...")
        instructions = evmdasm.EvmBytecode(bytecode).disassemble()
        disassembled = [str(instr) for instr in instructions]
        logging.info("Disassembled %d instructions.", len(disassembled))
        return disassembled
    except Exception as e:
        logging.exception("Disassembly failed: %s", e)
        return []


def output_instructions(instructions: List[str], output_file: Optional[Path]) -> None:
    """
    Print instructions to the console or write them to a file.
    """
    if not instructions:
        logging.warning("No instructions to output.")
        return

    if output_file:
        try:
            output_file.write_text("\n".join(instructions), encoding="utf-8")
            logging.info("Instructions written to: %s", output_file)
        except OSError as e:
            logging.error("Failed to write instructions to file %s: %s", output_file, e)
    else:
        print("\nDisassembled EVM Instructions:\n")
        for instr in instructions:
            print(instr)


def run_disassembler(bytecode: str, output_file: Optional[Path]) -> int:
    """
    Perform the validation, disassembly, and output steps.
    """
    if not is_valid_bytecode(bytecode):
        logging.error("Invalid bytecode. It must start with '0x' and contain only hexadecimal characters.")
        return EXIT_INVALID_BYTECODE

    instructions = disassemble_bytecode(bytecode)
    output_instructions(instructions, output_file)
    return EXIT_SUCCESS


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="EVM Bytecode Disassembler")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bytecode", type=str, help="Raw EVM bytecode string (must start with 0x)")
    group.add_argument("--file", type=Path, help="Path to a file containing EVM bytecode")

    parser.add_argument("--output", type=Path, help="Output file for disassembled instructions")
    parser.add_argument("--debug", action="store_true", help="Enable debug-level logging")

    return parser.parse_args()


def main() -> None:
    """
    Script entry point.
    """
    args = parse_args()
    setup_logging(logging.DEBUG if args.debug else logging.INFO)

    bytecode: Optional[str] = args.bytecode
    if args.file:
        bytecode = load_bytecode_from_file(args.file)

    if bytecode:
        exit_code = run_disassembler(bytecode, args.output)
        sys.exit(exit_code)
    else:
        logging.error("No valid bytecode was provided.")
        sys.exit(EXIT_READ_ERROR)


if __name__ == "__main__":
    main()

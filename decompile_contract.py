import argparse
import logging
import re
import sys
from typing import List, Optional

import evmdasm


def setup_logging(level: int = logging.INFO) -> None:
    """Configure logging format and level."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


def is_valid_bytecode(bytecode: str) -> bool:
    """Check if the bytecode is valid EVM format."""
    return bool(re.fullmatch(r"^0x[0-9a-fA-F]+$", bytecode))


def read_bytecode_from_file(file_path: str) -> Optional[str]:
    """Read and validate EVM bytecode from a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            bytecode = file.read().strip()
        if not bytecode:
            logging.error("File is empty: %s", file_path)
            return None
        if not is_valid_bytecode(bytecode):
            logging.error("Invalid bytecode format in file: %s", file_path)
            return None
        logging.debug("Successfully loaded bytecode from: %s", file_path)
        return bytecode
    except FileNotFoundError:
        logging.error("File not found: %s", file_path)
    except IOError as e:
        logging.error("Error reading file %s: %s", file_path, e)
    return None


def decompile_bytecode(bytecode: str) -> List[str]:
    """Decompile EVM bytecode into assembly instructions."""
    try:
        logging.debug("Decompiling bytecode...")
        evm_bytecode = evmdasm.EvmBytecode(bytecode)
        instructions = evm_bytecode.disassemble()
        formatted = [str(instr) for instr in instructions]
        logging.info("Successfully decompiled %d instructions.", len(formatted))
        return formatted
    except Exception as e:
        logging.exception("Failed to decompile bytecode: %s", e)
        return []


def display_instructions(instructions: List[str]) -> None:
    """Print EVM instructions to console."""
    if not instructions:
        logging.warning("No instructions to display.")
        return

    print("\nDecompiled EVM Instructions:\n")
    for instr in instructions:
        print(instr)


def write_instructions_to_file(instructions: List[str], output_path: str) -> None:
    """Write disassembled instructions to a file."""
    try:
        with open(output_path, "w", encoding="utf-8") as file:
            file.write("\n".join(instructions))
        logging.info("Instructions written to: %s", output_path)
    except IOError as e:
        logging.error("Failed to write instructions to file: %s", e)


def main(bytecode: str, output_file: Optional[str] = None) -> None:
    """Main execution logic."""
    if not is_valid_bytecode(bytecode):
        logging.error("Invalid bytecode. Must start with '0x' and contain only hex characters.")
        sys.exit(2)

    logging.info("Valid bytecode input. Starting decompilation...")
    instructions = decompile_bytecode(bytecode)

    if output_file:
        write_instructions_to_file(instructions, output_file)
    else:
        display_instructions(instructions)


if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="EVM Bytecode Decompiler")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bytecode", type=str, help="Raw EVM bytecode string (must start with 0x)")
    group.add_argument("--file", type=str, help="Path to file containing EVM bytecode")

    parser.add_argument("--output", type=str, help="Optional output file for instructions")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        setup_logging(logging.DEBUG)

    bytecode = args.bytecode or read_bytecode_from_file(args.file)
    if bytecode:
        main(bytecode, output_file=args.output)
    else:
        logging.error("No valid bytecode provided.")
        sys.exit(1)

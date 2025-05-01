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
    """
    Validate if a string is a proper EVM bytecode (starts with 0x and contains hex characters).
    """
    return bool(re.fullmatch(r"^0x[0-9a-fA-F]+$", bytecode)) and len(bytecode) > 2


def read_bytecode_from_file(file_path: str) -> Optional[str]:
    """
    Read bytecode from a file and validate its format.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            bytecode = f.read().strip()
        if not bytecode:
            logging.error("The file is empty: %s", file_path)
            return None
        if not is_valid_bytecode(bytecode):
            logging.error("Invalid bytecode format in file: %s", file_path)
            return None
        logging.debug("Successfully read bytecode from: %s", file_path)
        return bytecode
    except FileNotFoundError:
        logging.error("File not found: %s", file_path)
    except IOError as e:
        logging.error("Failed to read file %s: %s", file_path, e)
    return None


def decompile_bytecode(bytecode: str) -> List[str]:
    """
    Disassemble EVM bytecode into a list of instructions.
    """
    try:
        logging.debug("Starting decompilation...")
        evm_bytecode = evmdasm.EvmBytecode(bytecode)
        instructions = evm_bytecode.disassemble()
        logging.info("Decompiled %d instructions.", len(instructions))
        return instructions
    except Exception as e:
        logging.exception("Decompilation failed: %s", e)
        return []


def display_instructions(instructions: List[str]) -> None:
    """
    Display disassembled EVM instructions to the console.
    """
    if instructions:
        print("\nDecompiled Instructions:\n")
        print("\n".join(instructions))
    else:
        logging.warning("No instructions to display.")


def main(bytecode: str) -> None:
    """
    Validate and decompile the given EVM bytecode.
    """
    if not is_valid_bytecode(bytecode):
        logging.error("Invalid bytecode format. Must start with '0x' and contain only hex characters.")
        sys.exit(2)

    logging.info("Bytecode validation passed.")
    instructions = decompile_bytecode(bytecode)
    display_instructions(instructions)


if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="EVM Bytecode Decompiler")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bytecode", type=str, help="Raw EVM bytecode string (starting with 0x).")
    group.add_argument("--file", type=str, help="Path to a file containing EVM bytecode.")

    args = parser.parse_args()

    bytecode: Optional[str] = args.bytecode or read_bytecode_from_file(args.file)

    if bytecode:
        main(bytecode)
    else:
        logging.error("No valid EVM bytecode provided. Exiting.")
        sys.exit(1)

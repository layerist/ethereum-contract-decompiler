import argparse
import logging
import re
from typing import List, Optional

import evmdasm


def setup_logging(level: int = logging.INFO) -> None:
    """Set up the logging configuration."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


def is_valid_bytecode(bytecode: str) -> bool:
    """Check if the input is a valid EVM bytecode string."""
    return re.fullmatch(r"^0x[0-9a-fA-F]+$", bytecode) is not None


def read_bytecode_from_file(file_path: str) -> Optional[str]:
    """Read bytecode from a file and validate its format."""
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
        logging.error("Error reading file %s: %s", file_path, e)
    return None


def decompile_bytecode(bytecode: str) -> List[str]:
    """Disassemble EVM bytecode into human-readable instructions."""
    try:
        logging.debug("Starting decompilation process...")
        evm_bytecode = evmdasm.EvmBytecode(bytecode)
        instructions = evm_bytecode.disassemble()
        logging.debug("Decompilation successful. Instruction count: %d", len(instructions))
        return instructions
    except Exception as e:
        logging.exception("Failed to decompile bytecode: %s", e)
        return []


def display_instructions(instructions: List[str]) -> None:
    """Print the disassembled EVM instructions."""
    if instructions:
        logging.info("Decompiled instructions:")
        print("\n".join(instructions))
    else:
        logging.warning("No instructions to display.")


def main(bytecode: str) -> None:
    """Main function to validate and decompile EVM bytecode."""
    if not is_valid_bytecode(bytecode):
        logging.error("Invalid bytecode. It must start with '0x' and contain only hexadecimal characters.")
        exit(2)

    logging.info("Bytecode validation passed. Proceeding with decompilation...")
    instructions = decompile_bytecode(bytecode)
    display_instructions(instructions)


if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="EVM Bytecode Decompiler")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--bytecode", type=str, help="EVM bytecode as a hex string.")
    input_group.add_argument("--file", type=str, help="Path to file containing EVM bytecode.")

    args = parser.parse_args()

    bytecode = args.bytecode or read_bytecode_from_file(args.file)

    if bytecode:
        main(bytecode)
    else:
        logging.error("No valid EVM bytecode provided. Exiting.")
        exit(1)

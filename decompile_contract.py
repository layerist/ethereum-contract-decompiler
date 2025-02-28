import evmdasm
import argparse
import logging
import re
from typing import List, Optional


def setup_logging(level: int = logging.INFO) -> None:
    """Configure logging with the specified level and format."""
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")


def is_valid_bytecode(bytecode: str) -> bool:
    """Validate the EVM bytecode format."""
    return bool(re.fullmatch(r"^0x[0-9a-fA-F]+$", bytecode))


def decompile_bytecode(bytecode: str) -> Optional[List[str]]:
    """Decompile EVM bytecode into a list of human-readable instructions."""
    try:
        logging.debug("Decompiling bytecode...")
        bytecode_obj = evmdasm.EvmBytecode(bytecode)
        return bytecode_obj.disassemble()
    except Exception as e:
        logging.exception("Decompilation failed: %s", e)
        return None


def read_bytecode_from_file(file_path: str) -> Optional[str]:
    """Read and validate EVM bytecode from a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            bytecode = file.read().strip()
            if not bytecode:
                logging.error("The file is empty.")
                return None
            if not is_valid_bytecode(bytecode):
                logging.error("Invalid bytecode format in file: %s", file_path)
                return None
            logging.debug("Bytecode successfully read from %s", file_path)
            return bytecode
    except (FileNotFoundError, IOError) as e:
        logging.error("File error: %s", e)
    return None


def display_decompiled_code(instructions: Optional[List[str]]) -> None:
    """Print the decompiled EVM instructions."""
    if instructions:
        logging.info("Decompiled Contract Code:")
        print("\n".join(instructions))
    else:
        logging.error("No decompiled instructions available.")


def main(bytecode: str) -> None:
    """Main entry point for processing and decompiling EVM bytecode."""
    if not is_valid_bytecode(bytecode):
        logging.error("Invalid bytecode format. Must start with '0x' and contain hexadecimal characters.")
        exit(2)

    logging.info("Starting decompilation...")
    instructions = decompile_bytecode(bytecode)
    display_decompiled_code(instructions)


if __name__ == "__main__":
    setup_logging()
    
    parser = argparse.ArgumentParser(description="EVM Bytecode Decompiler")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--bytecode", type=str, help="EVM bytecode as a hexadecimal string.")
    input_group.add_argument("--file", type=str, help="Path to a file containing EVM bytecode.")
    
    args = parser.parse_args()
    
    bytecode = args.bytecode or (read_bytecode_from_file(args.file) if args.file else None)
    
    if not bytecode:
        logging.error("No valid EVM bytecode provided. Exiting.")
        exit(1)
    
    main(bytecode)

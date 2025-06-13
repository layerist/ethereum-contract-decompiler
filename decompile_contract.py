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
    """Configure logging format and level."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


def is_valid_bytecode(bytecode: str) -> bool:
    """Validate EVM bytecode format (must start with 0x and be hexadecimal)."""
    return bool(re.fullmatch(r"^0x[0-9a-fA-F]+$", bytecode))


def load_bytecode_from_file(file_path: Path) -> Optional[str]:
    """Read and validate EVM bytecode from a file."""
    try:
        content = file_path.read_text(encoding="utf-8").strip()
        if not content:
            logging.error("The file is empty: %s", file_path)
            return None
        if not is_valid_bytecode(content):
            logging.error("Invalid bytecode format in file: %s", file_path)
            return None
        logging.debug("Bytecode successfully loaded from file: %s", file_path)
        return content
    except FileNotFoundError:
        logging.error("File not found: %s", file_path)
    except Exception as e:
        logging.error("Failed to read file %s: %s", file_path, e)
    return None


def disassemble_bytecode(bytecode: str) -> List[str]:
    """Disassemble EVM bytecode into human-readable instructions."""
    try:
        logging.debug("Disassembling bytecode...")
        instructions = evmdasm.EvmBytecode(bytecode).disassemble()
        result = [str(instr) for instr in instructions]
        logging.info("Disassembled %d instructions.", len(result))
        return result
    except Exception as e:
        logging.exception("Disassembly failed: %s", e)
        return []


def output_instructions(instructions: List[str], output_file: Optional[Path]) -> None:
    """Output instructions to console or file."""
    if not instructions:
        logging.warning("No instructions to output.")
        return

    if output_file:
        try:
            output_file.write_text("\n".join(instructions), encoding="utf-8")
            logging.info("Instructions written to file: %s", output_file)
        except Exception as e:
            logging.error("Failed to write instructions to file %s: %s", output_file, e)
    else:
        print("\nDecompiled EVM Instructions:\n")
        for instr in instructions:
            print(instr)


def main(bytecode: str, output_file: Optional[Path]) -> int:
    """Main execution logic."""
    if not is_valid_bytecode(bytecode):
        logging.error("Invalid bytecode. It must start with '0x' and contain only hexadecimal characters.")
        return EXIT_INVALID_BYTECODE

    logging.info("Starting bytecode disassembly...")
    instructions = disassemble_bytecode(bytecode)
    output_instructions(instructions, output_file)
    return EXIT_SUCCESS


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EVM Bytecode Disassembler")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bytecode", type=str, help="Raw EVM bytecode string (must start with 0x)")
    group.add_argument("--file", type=Path, help="Path to file containing EVM bytecode")

    parser.add_argument("--output", type=Path, help="Path to output file for disassembled instructions")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    setup_logging(logging.DEBUG if args.debug else logging.INFO)

    bytecode_input = args.bytecode or load_bytecode_from_file(args.file)
    if bytecode_input:
        exit_code = main(bytecode_input, args.output)
        sys.exit(exit_code)
    else:
        logging.error("No valid bytecode provided.")
        sys.exit(EXIT_READ_ERROR)

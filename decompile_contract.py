import evmdasm
import argparse
import logging
from typing import List, Optional


def setup_logging(level: int = logging.INFO) -> None:
    """
    Configure logging with the specified level and format.
    """
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")


def decompile_bytecode(bytecode: str) -> Optional[List[str]]:
    """
    Decompile EVM bytecode into a list of human-readable instructions.

    Args:
        bytecode (str): Raw EVM bytecode as a hexadecimal string.

    Returns:
        Optional[List[str]]: Decompiled instructions, or None if decompilation fails.
    """
    try:
        return evmdasm.EvmBytecode(bytecode).disassemble()
    except Exception as e:
        logging.exception("Failed to decompile the provided bytecode. Ensure it is valid.")
        return None


def read_bytecode_from_file(file_path: str) -> Optional[str]:
    """
    Read and validate EVM bytecode from a file.

    Args:
        file_path (str): Path to the file containing EVM bytecode.

    Returns:
        Optional[str]: The bytecode string, or None if reading or validation fails.
    """
    try:
        with open(file_path, "r") as file:
            bytecode = file.read().strip()
            if not bytecode:
                raise ValueError("The file is empty or contains only whitespace.")
            return bytecode
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
    except IOError as e:
        logging.error(f"Error reading file '{file_path}': {e}")
    except ValueError as e:
        logging.error(f"Invalid file content: {e}")
    return None


def display_decompiled_code(instructions: Optional[List[str]]) -> None:
    """
    Print the decompiled EVM instructions to the console.

    Args:
        instructions (Optional[List[str]]): List of decompiled instructions.
    """
    if instructions:
        logging.info("Decompiled Contract Code:")
        for instruction in instructions:
            print(instruction)
    else:
        logging.error("No decompiled instructions available to display.")


def main(bytecode: str) -> None:
    """
    Main entry point for processing and decompiling EVM bytecode.

    Args:
        bytecode (str): EVM bytecode string to be decompiled.
    """
    logging.info("Starting the decompilation process...")
    instructions = decompile_bytecode(bytecode)
    display_decompiled_code(instructions)


if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="EVM Bytecode Decompiler")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--bytecode",
        type=str,
        help="EVM bytecode as a hexadecimal string (e.g., '0x60003560e01c').",
    )
    input_group.add_argument(
        "--file",
        type=str,
        help="Path to a file containing the raw EVM bytecode.",
    )

    args = parser.parse_args()

    # Retrieve the bytecode from the appropriate source
    bytecode = args.bytecode
    if not bytecode and args.file:
        bytecode = read_bytecode_from_file(args.file)

    if not bytecode:
        logging.error("Failed to retrieve valid EVM bytecode. Exiting.")
        exit(1)

    main(bytecode)

import evmdasm
import argparse
import logging
from sys import exit

def setup_logging(level=logging.INFO):
    """Configure logging with a specified level and a consistent format."""
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

def decompile_bytecode(bytecode):
    """
    Decompile EVM bytecode into human-readable instructions.
    
    Args:
        bytecode (str): The raw EVM bytecode as a string.
    
    Returns:
        list or None: Decompiled instructions, or None if an error occurs.
    """
    try:
        return evmdasm.EvmBytecode(bytecode).disassemble()
    except Exception as e:
        logging.exception("Failed to decompile bytecode")
        return None

def read_bytecode_from_file(file_path):
    """
    Load EVM bytecode from a specified file.
    
    Args:
        file_path (str): Path to the file with bytecode.
    
    Returns:
        str or None: The bytecode as a string, or None on error.
    """
    try:
        with open(file_path, 'r') as file:
            bytecode = file.read().strip()
            if not bytecode:
                raise ValueError("The file is empty.")
            return bytecode
    except (FileNotFoundError, IOError, ValueError) as e:
        logging.error(f"Error reading file '{file_path}': {e}")
        return None

def output_decompiled_code(instructions):
    """
    Display the decompiled EVM instructions if available.
    
    Args:
        instructions (list): List of decompiled instructions.
    """
    if instructions:
        logging.info("Decompiled Contract Code:")
        for instruction in instructions:
            print(instruction)
    else:
        logging.error("No instructions to display.")

def main(bytecode):
    """
    Execute decompilation for the provided EVM bytecode.
    
    Args:
        bytecode (str): EVM bytecode as a string.
    """
    instructions = decompile_bytecode(bytecode)
    output_decompiled_code(instructions)

if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="EVM Bytecode Decompiler")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--bytecode', type=str, help="Directly provide EVM bytecode as a string.")
    input_group.add_argument('--file', type=str, help="Path to the file containing the EVM bytecode.")
    
    args = parser.parse_args()

    bytecode = args.bytecode or read_bytecode_from_file(args.file)

    if not bytecode:
        logging.error("No valid bytecode provided. Exiting.")
        exit(1)

    main(bytecode)

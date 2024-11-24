import evmdasm
import argparse
import logging
from sys import exit

def setup_logging(level=logging.INFO):
    """
    Configure logging with the specified level and a consistent format.
    
    Args:
        level (int): Logging level (e.g., logging.INFO or logging.DEBUG).
    """
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

def decompile_bytecode(bytecode):
    """
    Decompile EVM bytecode into human-readable instructions.
    
    Args:
        bytecode (str): The raw EVM bytecode as a hexadecimal string.
    
    Returns:
        list or None: Decompiled instructions, or None if decompilation fails.
    """
    try:
        return evmdasm.EvmBytecode(bytecode).disassemble()
    except Exception as e:
        logging.exception("Failed to decompile bytecode.")
        return None

def read_bytecode_from_file(file_path):
    """
    Load EVM bytecode from a file.
    
    Args:
        file_path (str): Path to the file containing the EVM bytecode.
    
    Returns:
        str or None: The bytecode as a string, or None if reading fails.
    """
    try:
        with open(file_path, 'r') as file:
            bytecode = file.read().strip()
            if not bytecode:
                raise ValueError("The file is empty.")
            return bytecode
    except (FileNotFoundError, IOError) as e:
        logging.error(f"Error reading file '{file_path}': {e}")
    except ValueError as e:
        logging.error(f"Invalid file content: {e}")
    return None

def output_decompiled_code(instructions):
    """
    Display the decompiled EVM instructions.
    
    Args:
        instructions (list): List of decompiled instructions.
    """
    if instructions:
        logging.info("Decompiled Contract Code:")
        for instruction in instructions:
            print(instruction)
    else:
        logging.error("No instructions available to display.")

def main(bytecode):
    """
    Execute the decompilation process for the given EVM bytecode.
    
    Args:
        bytecode (str): EVM bytecode as a string.
    """
    logging.info("Starting decompilation process...")
    instructions = decompile_bytecode(bytecode)
    output_decompiled_code(instructions)

if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="EVM Bytecode Decompiler")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--bytecode', type=str, help="EVM bytecode as a hexadecimal string.")
    input_group.add_argument('--file', type=str, help="Path to the file containing the EVM bytecode.")
    
    args = parser.parse_args()

    bytecode = args.bytecode or read_bytecode_from_file(args.file)

    if not bytecode:
        logging.error("No valid bytecode provided. Exiting.")
        exit(1)

    main(bytecode)

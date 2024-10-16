import evmdasm
import argparse
import logging
import sys

def setup_logging(log_level=logging.INFO):
    """Configure logging with a specified level and a consistent format."""
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

def decompile_bytecode(bytecode):
    """
    Decompile EVM bytecode into human-readable instructions.
    
    Args:
        bytecode (str): The raw EVM bytecode as a string.
    
    Returns:
        list: A list of decompiled instructions, or None if an error occurs.
    """
    try:
        instructions = evmdasm.EvmBytecode(bytecode).disassemble()
        return instructions
    except Exception as e:
        logging.exception("Decompilation error")
        return None

def read_bytecode_from_file(file_path):
    """
    Read EVM bytecode from a file.
    
    Args:
        file_path (str): Path to the file containing bytecode.
    
    Returns:
        str: The EVM bytecode as a string, or None if an error occurs.
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

def output_decompiled_code(decompiled_code):
    """
    Output the decompiled EVM instructions.
    
    Args:
        decompiled_code (list): A list of decompiled instructions.
    """
    if decompiled_code:
        logging.info("Decompiled Contract Code:")
        for instruction in decompiled_code:
            print(instruction)
    else:
        logging.error("No instructions to display.")

def main(bytecode):
    """
    Handle the decompilation process of the provided EVM bytecode.
    
    Args:
        bytecode (str): EVM bytecode as a string.
    """
    decompiled_code = decompile_bytecode(bytecode)
    output_decompiled_code(decompiled_code)

if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="EVM Bytecode Decompiler")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--bytecode', type=str, help="Provide EVM bytecode as a string.")
    group.add_argument('--file', type=str, help="Path to the file containing the EVM bytecode.")
    
    args = parser.parse_args()

    bytecode = args.bytecode or read_bytecode_from_file(args.file)

    if not bytecode:
        logging.error("No valid bytecode provided. Exiting.")
        sys.exit(1)

    main(bytecode)

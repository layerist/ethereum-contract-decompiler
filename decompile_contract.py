import evmdasm
import argparse
import logging
import sys

def setup_logging():
    """Set up logging configuration with INFO level and a specific format."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def decompile_bytecode(bytecode):
    """
    Decompile EVM bytecode into human-readable instructions.

    Args:
        bytecode (str): The EVM bytecode to decompile.

    Returns:
        list: A list of decompiled instructions or None if an error occurs.
    """
    try:
        instructions = evmdasm.EvmBytecode(bytecode).disassemble()
        return instructions
    except Exception as e:
        logging.error(f"Failed to decompile bytecode: {e}")
        return None

def read_bytecode_from_file(file_path):
    """
    Read EVM bytecode from a file.

    Args:
        file_path (str): Path to the file containing the bytecode.

    Returns:
        str: The EVM bytecode as a string, or None if an error occurs.
    """
    try:
        with open(file_path, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        logging.error(f"File not found: '{file_path}'")
    except IOError as e:
        logging.error(f"Error reading file '{file_path}': {e}")
    return None

def main(bytecode):
    """
    Main function to handle the decompilation process of the provided EVM bytecode.

    Args:
        bytecode (str): The EVM bytecode to decompile.
    """
    decompiled_code = decompile_bytecode(bytecode)
    if decompiled_code:
        logging.info("Decompiled Contract Code:")
        for instruction in decompiled_code:
            print(instruction)
    else:
        logging.error("Decompilation failed.")

if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="EVM Bytecode Decompiler")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--bytecode', type=str, help="EVM bytecode as a string.")
    group.add_argument('--file', type=str, help="Path to a file containing the EVM bytecode.")
    
    args = parser.parse_args()

    bytecode = args.bytecode if args.bytecode else read_bytecode_from_file(args.file)

    if not bytecode:
        logging.error("No valid bytecode provided. Exiting.")
        sys.exit(1)

    main(bytecode)

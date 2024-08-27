import evmdasm
import argparse
import logging
import sys

def setup_logging():
    """Set up the logging configuration."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def decompile_bytecode(bytecode):
    """
    Decompile the given EVM bytecode into human-readable instructions.

    Args:
        bytecode (str): The EVM bytecode to decompile.

    Returns:
        list: A list of decompiled instructions or None if an error occurs.
    """
    try:
        instructions = evmdasm.EvmBytecode(bytecode).disassemble()
        return instructions
    except Exception as e:
        logging.error(f"Error decompiling bytecode: {e}")
        return None

def read_bytecode_from_file(file_path):
    """
    Read bytecode from a specified file.

    Args:
        file_path (str): Path to the file containing the EVM bytecode.

    Returns:
        str: The EVM bytecode as a string.
    """
    try:
        with open(file_path, 'r') as file:
            return file.read().strip()
    except Exception as e:
        logging.error(f"Error reading file '{file_path}': {e}")
        return None

def main(bytecode):
    """
    Main function to handle the decompilation of the EVM bytecode.

    Args:
        bytecode (str): The EVM bytecode to decompile.
    """
    decompiled_code = decompile_bytecode(bytecode)
    if decompiled_code:
        logging.info("Decompiled Contract Code:")
        for instruction in decompiled_code:
            print(instruction)
    else:
        logging.error("Failed to decompile the contract.")

if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="Decompile EVM bytecode.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--bytecode', type=str, help="The EVM bytecode as a string.")
    group.add_argument('--file', type=str, help="Path to a file containing the EVM bytecode.")
    
    args = parser.parse_args()

    bytecode = None
    if args.bytecode:
        bytecode = args.bytecode
    elif args.file:
        bytecode = read_bytecode_from_file(args.file)

    if not bytecode:
        logging.error("No valid bytecode provided. Exiting.")
        sys.exit(1)

    main(bytecode)

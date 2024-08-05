import evmdasm
import argparse
import logging

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def decompile_bytecode(bytecode):
    try:
        instructions = evmdasm.EvmBytecode(bytecode).disassemble()
        return instructions
    except Exception as e:
        logging.error(f"Error decompiling bytecode: {e}")
        return None

def main(bytecode):
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
    parser.add_argument('--bytecode', type=str, help="The EVM bytecode as a string.")
    parser.add_argument('--file', type=str, help="Path to a file containing the EVM bytecode.")
    args = parser.parse_args()

    bytecode = None
    if args.bytecode:
        bytecode = args.bytecode
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                bytecode = f.read().strip()
        except Exception as e:
            logging.error(f"Error reading file: {e}")
            exit(1)
    else:
        logging.error("You must provide either the bytecode string or the file path.")
        exit(1)

    if bytecode:
        main(bytecode)

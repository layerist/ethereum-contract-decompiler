import evmdasm
import argparse

def decompile_bytecode(bytecode):
    try:
        instructions = evmdasm.EvmBytecode(bytecode).disassemble()
        return instructions
    except Exception as e:
        print(f"Error decompiling bytecode: {e}")
        return None

def main(bytecode):
    decompiled_code = decompile_bytecode(bytecode)
    if decompiled_code:
        print("Decompiled Contract Code:")
        for instruction in decompiled_code:
            print(instruction)
    else:
        print("Failed to decompile the contract.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decompile EVM bytecode.")
    parser.add_argument('--bytecode', type=str, help="The EVM bytecode as a string.")
    parser.add_argument('--file', type=str, help="Path to a file containing the EVM bytecode.")

    args = parser.parse_args()

    if args.bytecode:
        bytecode = args.bytecode
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                bytecode = f.read().strip()
        except Exception as e:
            print(f"Error reading file: {e}")
            exit(1)
    else:
        print("You must provide either the bytecode string or the file path.")
        exit(1)

    main(bytecode)

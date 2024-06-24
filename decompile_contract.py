import evmdasm

def decompile_bytecode(bytecode):
    try:
        instructions = evmdasm.EvmBytecode(bytecode).disassemble()
        return instructions
    except Exception as e:
        print(f"Error decompiling bytecode: {e}")
        return None

def main():
    # Manually input the contract's bytecode here
    bytecode = (
        "608060405234801561001057600080fd5b5060405161010838038061010883398101604081905261002f91610045565b"
        # Add the full bytecode here
    )

    decompiled_code = decompile_bytecode(bytecode)
    if decompiled_code:
        print("Decompiled Contract Code:")
        for instruction in decompiled_code:
            print(instruction)
    else:
        print("Failed to decompile the contract.")

if __name__ == "__main__":
    main()

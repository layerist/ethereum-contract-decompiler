# Ethereum Contract Decompiler

This Python script decompiles an Ethereum smart contract bytecode to make it human-readable. You can manually input the contract's bytecode into the script.

## Requirements

- Python 3.6+
- `evmdasm`

## Installation

First, clone the repository:

```bash
git clone https://github.com/yourusername/ethereum-contract-decompiler.git
cd ethereum-contract-decompiler
```

Install the required dependencies:

```bash
pip install evmdasm
```

## Usage

To decompile a smart contract, manually input the bytecode into the script and run it:

1. Open `decompile_contract.py` in a text editor.
2. Locate the `bytecode` variable and replace the placeholder with the actual bytecode of the smart contract.
3. Run the script:

```bash
python decompile_contract.py
```

### Example

Replace the placeholder bytecode in `decompile_contract.py`:

```python
bytecode = (
    "608060405234801561001057600080fd5b5060405161010838038061010883398101604081905261002f91610045565b"
    # Add the full bytecode here
)
```

Then, execute the script:

```bash
python decompile_contract.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.
```

### Additional Notes

- The `evmdasm` library should handle the disassembly of the bytecode, making it easier to understand the operations performed by the smart contract.
- The provided bytecode in the example should be replaced with the actual bytecode of the contract you want to decompile.

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
"0x6080604052348015600f57600080fd5b506004361060325760003560e01c80630c55699c146037578063b49004e914605b575b600080fd5b60005460449061ffff1681565b60405161ffff909116815260200160405180910390f35b60616063565b005b60008054600191908190607a90849061ffff166096565b92506101000a81548161ffff021916908361ffff160217905550565b61ffff81811683821601908082111560be57634e487b7160e01b600052601160045260246000fd5b509291505056fea2646970667358221220666c87ec501268817295a4ca1fc6e3859faf241f38dd688f145135970920009264736f6c63430008120033
"
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

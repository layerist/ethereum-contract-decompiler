#!/usr/bin/env python3
"""
EVM Bytecode Disassembler
--------------------------
Disassembles Ethereum Virtual Machine (EVM) bytecode into human-readable instructions.

Supports:
    • Raw bytecode via --bytecode
    • File input via --file
    • Standard input via --stdin

Example usage:
    python disassembler.py --bytecode 0x6001600101
    python disassembler.py --file bytecode.txt --output output.txt
    cat bytecode.txt | python disassembler.py --stdin
"""

import argparse
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional, Union

import evmdasm

# Exit codes
EXIT_SUCCESS = 0
EXIT_INVALID_BYTECODE = 2
EXIT_READ_ERROR = 3
EXIT_DISASSEMBLY_ERROR = 4
EXIT_WRITE_ERROR = 5


def setup_logging(level: int = logging.INFO) -> None:
    """Configure the global logging format and level."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )


def is_valid_bytecode(bytecode: str) -> bool:
    """Return True if the string appears to be valid hexadecimal EVM bytecode."""
    return bool(re.fullmatch(r"(0x)?[0-9a-fA-F]+", bytecode.strip()))


def normalize_bytecode(bytecode: str) -> str:
    """Normalize bytecode to lowercase with a 0x prefix."""
    bc = bytecode.strip().lower()
    return bc if bc.startswith("0x") else "0x" + bc


def load_bytecode_from_file(file_path: Path) -> Optional[str]:
    """Load and validate EVM bytecode from a given file."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logging.error("File not found: %s", file_path)
        return None
    except OSError as e:
        logging.error("Error reading file %s: %s", file_path, e)
        return None

    content = re.sub(r"\s+", "", content)
    if not content:
        logging.error("File is empty: %s", file_path)
        return None

    if not is_valid_bytecode(content):
        logging.error("Invalid bytecode format in file: %s", file_path)
        return None

    return normalize_bytecode(content)


def disassemble_bytecode(
    bytecode: str,
    pretty: bool = False,
    json_out: bool = False
) -> Union[List[str], List[dict]]:
    """Disassemble the provided EVM bytecode into human-readable instructions."""
    try:
        instructions = evmdasm.EvmBytecode(bytecode).disassemble()
        if not instructions:
            logging.warning("No instructions found in bytecode.")
            return []

        if json_out:
            return [
                {
                    "pc": instr.pc,
                    "name": instr.name,
                    "operand": instr.operand,
                }
                for instr in instructions
            ]

        if pretty:
            max_len = max(len(instr.name) for instr in instructions)
            return [
                f"{instr.pc:04d}: {instr.name.ljust(max_len)} {instr.operand or ''}".rstrip()
                for instr in instructions
            ]

        return [f"{instr.pc:04d}: {instr.name} {instr.operand or ''}".strip() for instr in instructions]

    except Exception as e:
        logging.exception("Disassembly failed: %s", e)
        return []


def summarize_instructions(instructions: List[dict]) -> str:
    """Generate a short summary of instruction counts by opcode name."""
    counts = Counter(instr["name"] for instr in instructions)
    sorted_ops = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    summary_lines = ["Instruction Summary:"]
    summary_lines += [f"  {op:<10} {count}" for op, count in sorted_ops]
    return "\n".join(summary_lines)


def output_instructions(
    instructions: Union[List[str], List[dict]],
    output_file: Optional[Path],
    json_out: bool,
    summary: bool = False,
) -> int:
    """Print or write disassembled instructions to a file."""
    if not instructions:
        logging.error("No instructions to output.")
        return EXIT_DISASSEMBLY_ERROR

    if json_out:
        output_data = json.dumps(instructions, indent=2)
    else:
        header = f"Disassembled EVM Instructions ({len(instructions)} ops)"
        body = "\n".join(instructions)  # type: ignore
        output_data = f"{header}\n{'-' * len(header)}\n{body}"

    if summary and isinstance(instructions[0], dict):
        output_data += "\n\n" + summarize_instructions(instructions)  # type: ignore

    if output_file:
        try:
            output_file.write_text(output_data, encoding="utf-8")
            logging.info("Output written to: %s", output_file)
        except OSError as e:
            logging.error("Failed to write output file %s: %s", output_file, e)
            return EXIT_WRITE_ERROR
    else:
        print(output_data)

    return EXIT_SUCCESS


def read_from_stdin() -> Optional[str]:
    """Read and validate bytecode from standard input."""
    stdin_data = sys.stdin.read().strip()
    if not stdin_data:
        logging.error("No bytecode provided via stdin.")
        return None

    parts = re.split(r"\s+", stdin_data)
    valid_parts = [normalize_bytecode(p) for p in parts if is_valid_bytecode(p)]

    if len(valid_parts) == 1:
        return valid_parts[0]

    if len(valid_parts) > 1:
        logging.error("Multiple bytecode sequences detected. Provide only one at a time.")
        return None

    logging.error("No valid bytecode found in stdin input.")
    return None


def run_disassembler(
    bytecode: str,
    output_file: Optional[Path],
    pretty: bool,
    json_out: bool,
    summary: bool = False,
) -> int:
    """Validate, disassemble, and output bytecode."""
    if not is_valid_bytecode(bytecode):
        logging.error("Invalid bytecode: must be hexadecimal with optional 0x prefix.")
        return EXIT_INVALID_BYTECODE

    bytecode = normalize_bytecode(bytecode)
    instructions = disassemble_bytecode(bytecode, pretty=pretty, json_out=json_out)

    if not instructions:
        return EXIT_DISASSEMBLY_ERROR

    return output_instructions(instructions, output_file, json_out, summary)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Disassemble Ethereum Virtual Machine (EVM) bytecode.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="EVM Disassembler 1.4")

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bytecode", type=str, help="Raw EVM bytecode string")
    source.add_argument("--file", type=Path, help="File containing EVM bytecode")
    source.add_argument("--stdin", action="store_true", help="Read bytecode from standard input")

    parser.add_argument("--output", type=Path, help="Write disassembled instructions to this file")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--pretty", action="store_true", help="Aligned human-readable output")
    parser.add_argument("--json", action="store_true", help="Output JSON-formatted instructions")
    parser.add_argument("--summary", action="store_true", help="Include opcode summary statistics")

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()
    setup_logging(logging.DEBUG if args.debug else logging.INFO)

    bytecode: Optional[str] = None

    if args.bytecode:
        bytecode = args.bytecode
    elif args.file:
        bytecode = load_bytecode_from_file(args.file)
    elif args.stdin:
        bytecode = read_from_stdin()

    if not bytecode:
        logging.error("No valid bytecode provided.")
        return EXIT_READ_ERROR

    return run_disassembler(bytecode, args.output, args.pretty, args.json, args.summary)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)

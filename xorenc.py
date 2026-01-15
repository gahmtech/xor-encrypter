"""
XOR 3ncryp73r

A command-line utility to XOR-obfuscate binary or hex-encoded input files
and emit the result in binary, Python, or C source formats.

⚠ XOR is reversible and should not be used for cryptographic security.
"""
import argparse
import sys
import pyfiglet
from pathlib import Path


ascii_logo = pyfiglet.figlet_format("XOR 3ncryp73r")


def read_input_file(path: Path) -> bytes:
    """
    Read input data from a file.

    Supported formats:
        - .bin: Raw binary bytes
        - .txt: Hex-encoded text (whitespace allowed)

    Args:
        path (Path): Path to the input file.

    Returns:
        bytes: Parsed input data.

    Raises:
        ValueError: If the file type is unsupported or hex decoding fails.
    """
    if path.suffix.lower() == ".bin":
        return path.read_bytes()

    if path.suffix.lower() == ".txt":
        text = path.read_text(encoding="utf-8")
        hex_str = "".join(text.split())
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            raise ValueError("[-] TXT input must be valid hex")

    raise ValueError("Unsupported input file type (use .bin or .txt)")


def xor_data(data: bytes, key: bytes) -> bytes:
    """
    XOR data with a repeating key.

    Args:
        data (bytes): Input data to obfuscate.
        key (bytes): XOR key (must not be empty).

    Returns:
        bytes: XOR-obfuscated output.

    Raises:
        ValueError: If the key is empty.
    """
    if not key:
        raise ValueError("[-] XOR key must not be empty")
    out = []
    key_len = len(key)

    for i, byte in enumerate(data):
        out.append(byte ^ key[i % key_len])

    return bytes(out)
#    return bytes(d ^ k for d, k in zip(data, cycle(key)))


def output_bin(data: bytes, outfile: Path):
    """
    Write raw binary output to a file.

    Args:
        data (bytes): Obfuscated data.
        outfile (Path): Output file path.
    """
    outfile.write_bytes(data)


def output_python(data: bytes, key: bytes, outfile: Path):
    """
    Write XOR payload as a Python source file.

    The output contains:
        - key (bytes)
        - payload (bytes)
        - payload length

    Args:
        data (bytes): Obfuscated payload.
        key (bytes): XOR key used.
        outfile (Path): Output .py file path.
    """
    with outfile.open("w", encoding="utf-8") as f:
        f.write("# Auto-generated XOR payload\n\n")
        f.write(f"key = {repr(key)}\n")
        f.write(f"payload = {repr(data)}\n")
        f.write(f"payload_len = {len(data)}\n")


def output_c(data: bytes, out_file: Path, wrap=16):
    """
    Write XOR payload as a C source array.

    Args:
        data (bytes): Obfuscated payload.
        out_file (Path): Output .c file.
        wrap (int): Number of bytes per line.
    """
    with out_file.open("w", encoding="utf-8") as f:
        f.write("unsigned char xored_shellcode[] = {\n    ")

        for i, b in enumerate(data):
            f.write(f"0x{b:02X}")
            if i != len(data) - 1:
                f.write(", ")

            if (i + 1) % wrap == 0 and i != len(data) - 1:
                f.write("\n    ")

        f.write("\n};\n")
        f.write(f"unsigned int xored_shellcode_len = {len(data)};\n")


def main():
    """
    Parse command-line arguments and run the XOR obfuscation workflow.

    Handles:
        - Input parsing (file or stdin)
        - Key decoding (ASCII or hex)
        - XOR obfuscation
        - Output formatting
    """
    parser = argparse.ArgumentParser(prog="xorenc", 
                                     description="XOR obfuscate a binary or hex file", 
                                     epilog="XOR is reversible and should not be used for cryptographic security."
                                     )
    parser.add_argument("input", help="Input file (.bin or .txt hex), or '-' for stdin")
    parser.add_argument("-o", "--output", required=True, help="Output file")
    parser.add_argument("-k", "--key", required=True, help="XOR key string")
    parser.add_argument("-f", "--format", choices=["bin", "python", "c"], default="bin", help="Output format")
    args = parser.parse_args()

    output_path = Path(args.output)
    if args.key.startswith("hex:"):
        key_bytes = bytes.fromhex(args.key[4:])
    else:
        key_bytes = args.key.encode()

    # --- INPUT ---
    if args.input == "-":
        raw = sys.stdin.read()
        try:
            data = bytes.fromhex("".join(raw.split()))
        except ValueError:
            data = raw.encode()    
    else:
        input_file = Path(args.input)
        if not input_file.exists():
            sys.exit("[-] Input file not found")
        try:
            data = read_input_file(input_file)
        except ValueError as e:
            sys.exit(f"[-] {e}")

    # --- XOR ---
    try:
        obfuscated = xor_data(data, key_bytes)
    except ValueError as e:
        sys.exit(f"[-] {e}")

    # --- OUTPUT ---
    if args.format == "bin":
        output_bin(obfuscated, output_path)
    elif args.format == "python":
        output_python(obfuscated, key_bytes, output_path)
    elif args.format == "c":
        output_c(obfuscated, output_path)

    print(ascii_logo)
    print(f"[+] Payload created to file: {output_path}")
    print("[!] XOR is reversible — do not reuse keys")


if __name__ == "__main__":
    main()

import argparse
import sys
import pyfiglet
from pathlib import Path
from itertools import cycle


ascii_logo = pyfiglet.figlet_format("XOR 3ncryp73r")


def read_input_file(path: Path) -> bytes:
    """
    Read input file:
      - .bin → raw bytes
      - .txt → hex-encoded text (spaces/newlines allowed)
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
    if not key:
        raise ValueError("[-] XOR key must not be empty")

    return bytes(d ^ k for d, k in zip(data, cycle(key)))


def output_bin(data: bytes, outfile: Path):
    outfile.write_bytes(data)


def output_python(data: bytes, key: bytes, outfile: Path):
    with outfile.open("w", encoding="utf-8") as f:
        f.write("# Auto-generated XOR payload\n\n")
        f.write(f"key = {repr(key)}\n")
        f.write(f"payload = {repr(data)}\n")
        f.write(f"payload_len = {len(data)}\n")


def output_c(data: bytes, out_path: Path, wrap=16):
    with out_path.open("w", encoding="utf-8") as f:
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
    parser = argparse.ArgumentParser(description="XOR obfuscate a binary or hex file")
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
    # key_bytes = args.key.encode()

    # --- INPUT ---
    if args.input == "-":
        raw = sys.stdin.read()
        try:
            data = bytes.fromhex("".join(raw.split()))
        except ValueError:
            data = raw.encode()    
    
    #     data = sys.stdin.buffer.read()
    else:
        input_path = Path(args.input)
        if not input_path.exists():
            sys.exit("[-] Input file not found")
        try:
            data = read_input_file(input_path)
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

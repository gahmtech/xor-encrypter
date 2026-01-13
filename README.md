# XOR 3ncryp73r

**XOR 3ncryp73r** is a Python command-line utility for XOR-obfuscating binary data or hex-encoded text files.  It supports multiple output formats and flexible input methods, making it useful for payload obfuscation, testing, and educational purposes.

> ⚠️ **Warning**  
> XOR encryption is reversible and **not cryptographically secure**.  
> Do **not** reuse keys and do **not** rely on this tool for real security.

> ⚠️ **DISCLAIMER**
> 
>This tool is provided for **educational and testing purposes only**.
>The author is **not** responsible for misuse. Use your brain!
---

## Features

- XOR-encode binary or hex data
- Accept input from files or standard input
- Repeating XOR key support
- Multiple output formats:
  - Raw binary
  - Python source file
  - C source file
- Supports string keys and hex keys

---

## Requirements

- Python **3.8+**
- `pyfiglet`

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/xor-3ncryp73r.git
cd xor-3ncryp73r
```
### 2. Create a virtual enviroment and activate
```bash
python3 -m venv venv
source venv/bin/activate   # Linux / macOS
venv\Scripts\activate      # Windows
```
### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### Usage
```bash
python3 xor_encryptor.py <inputfile> -o <outputfile> -k <key> -f <output format>
```
#### Arguments
| Argument       | Description                                          |
| -------------- | ---------------------------------------------------- |
| `input`        | Input file (`.bin`, `.txt`) or `-` for stdin         |
| `-o, --output` | Output file path                                     |
| `-k, --key`    | XOR key string or `hex:` prefixed hex key            |
| `-f, --format` | Output format: `bin`, `python`, `c` (default: `bin`) |

#### Input Formats
`.bin`
- Read as raw bytes

`.txt`
- Interpreted as hex-encoded text
- Spaces and newlines are allowed

Example of .txt file:
```txt
90 90 90 CC
```
---

#### Output Formats
Binary (`bin`)
Writes raw XOR-encoded bytes to a file.

Python (`python`)
Generates a Python file containing:
- XOR key
- Obfuscated payload
- Payload length

C (`c`)
Generates a C source file with a byte array suitable for embedding.

---

### Examples

##### XOR a binary file → binary output
```bash
python xor_encryptor.py shellcode.bin -o xored.bin -k secretkey
```

##### XOR a hex text file → C source output
```bash
python xor_encryptor.py payload.txt -o payload.c -k mykey -f c
```

##### Use a hex-encoded key
```bash
python xor_encryptor.py input.bin -o output.bin -k hex:414243
```
*(Key = `ABC`)*

---

##### Generate a Python payload file
```bash
python xor_encryptor.py payload.bin -o payload.py -k supersecret -f python
```
Example output:
```bash
key = b'supersecret'
payload = b'\x12\x34\x56'
payload_len = 3
```

##### Read hex input from stdin
```bash
echo "90 90 CC" | python xor_encryptor.py - -o out.bin -k testkey
```

---

#### Notes

- XOR is symmetric: running the tool again with the same key will decode the data.
- Empty keys are not allowed.
- Invalid hex input will raise an error.
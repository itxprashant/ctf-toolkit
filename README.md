# CTF Scripts Toolkit 🛠️🚩

A comprehensive, automated, and interactive Python toolkit designed to quickly solve beginner-to-intermediate Capture The Flag (CTF) challenges across all major categories — Crypto, Forensics, Web, Network, Binary Analysis, and Password Cracking.

![Python Version](https://img.shields.io/badge/Python-3.8%2B-brightgreen)
![Tools](https://img.shields.io/badge/Tools-20%2B-blue)
![Interface](https://img.shields.io/badge/Interface-Interactive_TUI-purple)

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Interactive TUI Launcher](#interactive-tui-launcher)
- [Tools Reference](#tools-reference)
  - [🔑 Cryptography](#-cryptography-crypto)
  - [🌐 Web Exploitation](#-web-exploitation-web)
  - [📡 Network Analysis](#-network--packet-analysis-network)
  - [🕵️ Forensics & Steganography](#️-forensics--steganography-forensics)
  - [🔓 Password Brute Force](#-password-brute-force-bruteforce)
  - [🔬 Binary Analysis](#-binary-analysis-carving)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **20+ specialized tools** organized into 7 categories
- **Interactive TUI Launcher** — browse and run tools from a beautiful `curses`-based interface
- **Integrated File Browser** — a `ranger`/`yazi`-like file selector that pops up when a tool needs a file argument
- **Flag Detection** — most tools automatically highlight text matching common CTF flag formats (`flag{}`, `CTF{}`, `picoCTF{}`, etc.)
- **Standalone Execution** — every script can be run independently with full `argparse` help
- **Dependency Aware** — scripts detect missing libraries and provide install commands
- **JSON Output** — many tools support `--json` for piping into other programs

---

## Quick Start

```bash
# Clone
git clone https://github.com/yourusername/ctf-scripts.git
cd ctf-scripts

# Install dependencies
pip3 install pycryptodome scapy requests matplotlib scipy numpy Pillow

# Launch the interactive TUI
./ctf
```

---

## Installation

### 1. Python Dependencies

The core forensics and brute-force tools work with Python standard library only. Advanced tools require additional packages:

```bash
# Required for full functionality
pip3 install pycryptodome   # RSA math (crypto/rsa_toolkit.py)
pip3 install scapy          # PCAP parsing (network/pcap_extractor.py, usb_hid_parser.py)
pip3 install requests       # HTTP requests (web/lfi_scanner.py, sqli_probe.py)
pip3 install matplotlib     # Plotting (forensics/audio_steg.py, network/usb_hid_parser.py)
pip3 install scipy          # Audio analysis (forensics/audio_steg.py)
pip3 install numpy          # Numerical ops (forensics/audio_steg.py)
pip3 install Pillow         # Image processing (forensics/advanced_zsteg.py)

# Or install everything at once:
pip3 install pycryptodome scapy requests matplotlib scipy numpy Pillow
```

### 2. System Dependencies (Optional but Recommended)

```bash
# exiftool — massively enhances metadata extraction (400+ file formats)
sudo apt install libimage-exiftool-perl

# tshark — improves USB HID packet extraction accuracy
sudo apt install tshark
```

### 3. Make the Launcher Executable

```bash
chmod +x ctf
```

---

## Interactive TUI Launcher

The `ctf` script is the main entry point. It provides a full-screen terminal interface to browse categories and tools.

```bash
./ctf
```

### Controls

| Key | Action |
|-----|--------|
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `Enter` | Select category / Run tool |
| `Esc` | Go back |
| `q` | Quit |

### File Browser

When a tool requires a file argument (like `<file>`, `<image>`, or `<wordlist>`), the TUI automatically opens an integrated file browser:

| Key | Action |
|-----|--------|
| `↑↓` / `jk` | Navigate files |
| `←` / `h` | Go to parent directory |
| `→` / `l` or `Enter` | Open directory / Select file |
| `.` | Toggle hidden files |
| `/` | Search / filter |
| `~` | Jump to home directory |
| `g` / `G` | Jump to top / bottom |

---

## Tools Reference

### 🔑 Cryptography (`crypto/`)

#### `rsa_toolkit.py` — RSA Attack Automation

Automates the most common RSA attacks found in CTF challenges.

**Attacks supported:**
- **Wiener's Attack** — Exploits small private key `d` via continued fraction expansion
- **Fermat's Factorization** — Exploits primes `p` and `q` that are too close together
- **Small `e` Attack** — Computes the integer `e`-th root when `m^e < n`
- **Common Modulus** — Decrypts when the same message is encrypted with the same `n` but different `e` values

```bash
# Try all single-target attacks automatically
python3 crypto/rsa_toolkit.py single -n <modulus> -e <exponent> -c <ciphertext>

# Common Modulus attack
python3 crypto/rsa_toolkit.py common-mod -n <n> --e1 <e1> --c1 <c1> --e2 <e2> --c2 <c2>
```

---

#### `xor_bruteforcer.py` — XOR Decryption

Breaks XOR encryption using frequency analysis and statistical scoring.

**Modes:**
- **Single-byte** — Tries all 256 keys, scores results by English letter frequency (Chi-squared)
- **Repeating-key** — Guesses key length via Hamming distance, then solves each column

```bash
# Single-byte XOR brute force
python3 crypto/xor_bruteforcer.py ciphertext.bin single

# From hex string
python3 crypto/xor_bruteforcer.py '1b37373331363f78151b7f2b783431333d' --hex single

# Repeating-key XOR
python3 crypto/xor_bruteforcer.py encrypted.bin repeating

# Repeating-key with known key length
python3 crypto/xor_bruteforcer.py encrypted.bin repeating -k 5
```

---

#### `magic_decoder.py` — Recursive Encoding Decoder

A CLI "CyberChef Magic" that recursively tries decoding layers until it finds readable text or a flag.

**Encodings tested:** Base64, Base32, Base58, Base85, Hex, Decimal, Octal, Binary, URL-encoding, ROT13

```bash
# Decode a string
python3 crypto/magic_decoder.py 'Wm14blEzTmpNak16'

# Decode from a file
python3 crypto/magic_decoder.py @encoded.txt

# Increase recursion depth
python3 crypto/magic_decoder.py 'nested_encodings_here' -d 15
```

---

#### `cipher_solver.py` — Classical Cipher Breaker

Automatically solves historical ciphers commonly found in CTF challenges. Includes an auto-detect mode that analyzes input and suggests the most likely cipher type.

**Ciphers supported:**

| Cipher | Subcommand | Technique |
|--------|------------|-----------|
| Caesar | `caesar` | Brute-forces all 25 shifts, ranked by combined Chi-squared + dictionary score |
| ROT13 | `rot13` | Dedicated ROT13 decoder (Caesar shift 13) |
| ROT47 | `rot47` | Rotates all printable ASCII (33-126) by 47 positions |
| Atbash | `atbash` | Mirror substitution (A↔Z, B↔Y, ...) |
| Affine | `affine` | Brute-forces all 312 valid (a, b) key pairs for `E(x) = (ax+b) mod 26` |
| Vigenère | `vigenere` | Auto key-length detection via Index of Coincidence, or manual `-k KEY` |
| Rail Fence | `railfence` | Brute-forces rail counts 2–20 for zigzag transposition |
| Substitution | `substitution` | Frequency-analysis mapping with full cipher→plain table output |
| Morse Code | `morse` | Decodes `./-` , unicode dots/dashes, and binary `0/1` Morse |
| Base Encoding | `base` | Auto-detects and decodes Base16, Base32, Base64, Base85, ASCII85 |
| Baconian | `bacon` | Decodes A/B, binary `0/1`, and case-based (upper/lower) Bacon cipher |
| Auto-detect | `detect` | Heuristic analysis with confidence scores, auto-runs top suggestions |
| All | `all` | Runs every cipher solver in sequence |

**Scoring features:**
- Chi-squared frequency analysis against English letter distributions
- Dictionary validation using 180+ common English and CTF-relevant words
- Automatic CTF flag detection (`FLAG{}`, `CTF{}`) with highlighted output

```bash
# Auto-detect cipher type and solve
python3 crypto/cipher_solver.py 'SGVsbG8gV29ybGQ=' detect

# Try all classical ciphers at once
python3 crypto/cipher_solver.py 'Gur synt vf cvpbPGS{ebg13}' all

# Caesar only
python3 crypto/cipher_solver.py 'Khoor Zruog' caesar

# ROT13
python3 crypto/cipher_solver.py 'Uryyb Jbeyq' rot13

# Affine cipher brute-force
python3 crypto/cipher_solver.py 'Fuuiqn Njkxg' affine

# Vigenère with a known key
python3 crypto/cipher_solver.py 'LXFOPVEFRNHR' vigenere -k LEMON

# Rail Fence
python3 crypto/cipher_solver.py 'Horel ollWd' railfence

# Morse code
python3 crypto/cipher_solver.py '.... . .-.. .-.. --- / .-- --- .-. .-.. -..' morse

# Base encoding detection
python3 crypto/cipher_solver.py 'Q1RGe2Jhc2U2NF9pc19lYXN5fQ==' base

# Baconian cipher (A/B groups)
python3 crypto/cipher_solver.py 'AABBB AABAA ABABB ABABB ABBBA' bacon

# From a file
python3 crypto/cipher_solver.py @challenge.txt all
```

---

### 🌐 Web Exploitation (`web/`)

#### `lfi_scanner.py` — Local File Inclusion Scanner

Automatically tests URL parameters for path traversal and PHP wrapper vulnerabilities.

**Payloads include:**
- Simple traversal (`../../etc/passwd`) up to 8 levels deep
- Null-byte injection (`%00`)
- Double URL-encoding bypass (`%252e%252e%252f`)
- PHP filter wrappers (`php://filter/convert.base64-encode/resource=`)
- WAF evasion encodings

```bash
# Test with INJECT placeholder
python3 web/lfi_scanner.py 'http://target.com/index.php?page=INJECT'

# Test a specific parameter
python3 web/lfi_scanner.py 'http://target.com/view' --param file

# Target a specific file
python3 web/lfi_scanner.py 'http://target.com/?page=INJECT' -t flag.txt

# Also try to dump PHP source code
python3 web/lfi_scanner.py 'http://target.com/?page=INJECT' --php

# With authentication cookies
python3 web/lfi_scanner.py 'http://target.com/?f=INJECT' -c 'session=abc123'
```

---

#### `sqli_probe.py` — SQL Injection Detector

Sends syntax-breaking characters and time-based payloads to identify SQL injection entry points.

**Detection methods:**
- **Error-based** — Looks for MySQL, PostgreSQL, SQLite, Oracle, and SQL Server error strings
- **Time-based** — Measures response time after injecting `SLEEP()` / `WAITFOR DELAY` commands

```bash
# Test with INJECT placeholder
python3 web/sqli_probe.py 'http://target.com/item.php?id=INJECT'

# Test a specific parameter
python3 web/sqli_probe.py 'http://target.com/search' -p query

# With cookies
python3 web/sqli_probe.py 'http://target.com/?id=INJECT' -c 'token=xyz'
```

---

### 📡 Network & Packet Analysis (`network/`)

#### `pcap_extractor.py` — PCAP Forensics

Parses `.pcap` / `.pcapng` files to extract useful information without opening Wireshark.

**Capabilities:**
- Dumps all unique DNS queries
- Finds plaintext credentials (HTTP Basic Auth, HTTP forms, FTP `USER`/`PASS`)
- Reassembles and extracts files from HTTP `200 OK` responses

```bash
# Run all analyses
python3 network/pcap_extractor.py capture.pcap

# DNS queries only
python3 network/pcap_extractor.py capture.pcap --dns

# Credentials only
python3 network/pcap_extractor.py capture.pcap --creds

# Extract HTTP files to a custom directory
python3 network/pcap_extractor.py capture.pcap --files -o ./loot/
```

---

#### `usb_hid_parser.py` — USB Keystroke & Mouse Reconstructor

Translates USB HID packets from PCAPs into readable keystrokes or visual mouse plots.

**Features:**
- Full keyboard map with shift, caps lock, backspace handling
- Mouse movement plotting using `matplotlib` (draws the flag!)
- Uses `tshark` for accurate extraction when available, falls back to `scapy`

```bash
# Reconstruct keyboard keystrokes
python3 network/usb_hid_parser.py usb_capture.pcap -k

# Plot mouse movements
python3 network/usb_hid_parser.py usb_capture.pcap -m

# Save mouse plot to specific file
python3 network/usb_hid_parser.py usb_capture.pcap -m -p flag_drawing.png

# Run both analyses
python3 network/usb_hid_parser.py usb_capture.pcap
```

---

### 🕵️ Forensics & Steganography (`forensics/`)

#### `metadata_extractor.py` — Exhaustive Metadata Dumper

Powered by `exiftool` for maximum coverage (400+ file formats). Falls back to a built-in Python parser if `exiftool` is not installed.

**Highlights:**
- Groups metadata by category (EXIF, IPTC, XMP, System, GPS, etc.)
- Auto-generates Google Maps links from GPS coordinates
- Auto-detects CTF flag patterns in any metadata field
- Supports JSON output for scripting

```bash
# Extract all metadata
python3 forensics/metadata_extractor.py photo.jpg

# Deep scan (embedded files, unknown tags)
python3 forensics/metadata_extractor.py firmware.bin --all

# JSON output
python3 forensics/metadata_extractor.py mystery.png --json

# Raw exiftool output
python3 forensics/metadata_extractor.py document.pdf --raw
```

---

#### `advanced_zsteg.py` — Advanced LSB Steganography

A pure-Python port of the essential `zsteg` features. Scans all bit-planes across all color channels.

**Channels tested:** R, G, B, A, RGB, BGR, RGBA, ABGR  
**Bit planes:** LSB (bit 0) by default, all 8 bits with `--all`  
**Bit orders:** LSB-first and MSB-first

```bash
# Quick LSB scan
python3 forensics/advanced_zsteg.py stego.png

# Full scan (all 8 bit planes, both bit orders)
python3 forensics/advanced_zsteg.py stego.png -a

# Extract a specific payload
python3 forensics/advanced_zsteg.py stego.png -e 'RGB,lsb' -o hidden.zip
```

---

#### `audio_steg.py` — Audio Forensics

Reveals hidden messages in audio files by generating spectrograms and extracting LSB data.

```bash
# Generate a spectrogram (saves to spectrogram.png)
python3 forensics/audio_steg.py audio.wav -s

# Grayscale spectrogram
python3 forensics/audio_steg.py audio.wav -s --cmap gray

# Extract LSB steganography
python3 forensics/audio_steg.py audio.wav -l

# Extract a specific bit plane
python3 forensics/audio_steg.py audio.wav -l --bit 1

# Run both analyses
python3 forensics/audio_steg.py audio.wav
```

---

#### Other Forensics Tools

| Tool | Description | Example |
|------|-------------|---------|
| `file_analyzer.py` | Magic bytes, file type detection, entropy | `python3 forensics/file_analyzer.py mystery.bin` |
| `strings_finder.py` | Extract strings with flag pattern matching | `python3 forensics/strings_finder.py firmware.bin` |
| `hex_viewer.py` | Hex dump with search and highlighting | `python3 forensics/hex_viewer.py binary.dat --search "flag"` |
| `steg_basic.py` | Simple LSB extraction, image comparison | `python3 forensics/steg_basic.py lsb image.png` |

---

### 🔓 Password Brute Force (`bruteforce/`)

| Tool | Description | Example |
|------|-------------|---------|
| `hash_cracker.py` | MD5/SHA1/SHA256 wordlist + mutation attacks | `python3 bruteforce/hash_cracker.py <hash> -w rockyou.txt` |
| `archive_cracker.py` | ZIP & PDF password brute force | `python3 bruteforce/archive_cracker.py secret.zip -w wordlist.txt` |
| `wordlist_gen.py` | Custom wordlist generation with mutations | `python3 bruteforce/wordlist_gen.py --base-words admin,pass --rules full` |
| `jwt_cracker.py` | Decode, brute force HMAC secrets, forge tokens | `python3 bruteforce/jwt_cracker.py decode <token>` |

---

### 🔬 Binary Analysis (`carving/`)

| Tool | Description | Example |
|------|-------------|---------|
| `file_carver.py` | Binwalk alternative — 35+ file signatures | `python3 carving/file_carver.py firmware.bin --extract` |
| `entropy_visualizer.py` | Block entropy heatmap (terminal + PNG) | `python3 carving/entropy_visualizer.py firmware.bin --regions` |
| `firmware_analyzer.py` | Header/filesystem/bootloader scanner | `python3 carving/firmware_analyzer.py firmware.bin --all` |

---

## Project Structure

```
ctf-scripts/
├── ctf                          # Interactive TUI launcher (main entry point)
├── README.md
│
├── forensics/                   # Forensics & steganography tools
│   ├── file_analyzer.py
│   ├── metadata_extractor.py
│   ├── strings_finder.py
│   ├── hex_viewer.py
│   ├── steg_basic.py
│   ├── advanced_zsteg.py
│   └── audio_steg.py
│
├── bruteforce/                  # Password cracking tools
│   ├── hash_cracker.py
│   ├── archive_cracker.py
│   ├── wordlist_gen.py
│   └── jwt_cracker.py
│
├── carving/                     # Binary analysis tools
│   ├── file_carver.py
│   ├── entropy_visualizer.py
│   └── firmware_analyzer.py
│
├── crypto/                      # Cryptography tools
│   ├── rsa_toolkit.py
│   ├── xor_bruteforcer.py
│   ├── magic_decoder.py
│   └── cipher_solver.py
│
├── web/                         # Web exploitation tools
│   ├── lfi_scanner.py
│   └── sqli_probe.py
│
└── network/                     # Network forensics tools
    ├── pcap_extractor.py
    └── usb_hid_parser.py
```

---

## Contributing

Contributions are welcome! If you have a useful CTF script or want to improve an existing tool:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-tool`)
3. Add your script to the appropriate category directory
4. Update the `CATEGORIES` list in `ctf` to include your tool
5. Submit a Pull Request

---

## License

MIT License

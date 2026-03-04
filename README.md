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
- **Flag Detection** — most tools automatically highlight text matching common CTF flag formats (`flag{}`, `CTF{}`, `picoCTF{}`, `HTB{}`, etc.)
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

# ffmpeg — enables non-WAV audio analysis (MP3, FLAC, OGG)
sudo apt install ffmpeg

# gmpy2 — speeds up RSA math significantly
pip3 install gmpy2
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

Automatically tries multiple attacks to break weak RSA.

**Attacks:**
- **Wiener's Attack** — small private key `d`
- **Fermat's Factorization** — close `p` and `q`
- **Small `e` Attack** — `m^e < n` cube root
- **Common Modulus** — same `n`, different `e`
- **Pollard's p-1** — smooth prime factors
- **Pollard's Rho** — small moduli
- **FactorDB Lookup** — online factor database query
- **Hastad's Broadcast** — same `m` sent to multiple recipients
- **PEM/DER Key Parsing** — extract `n`, `e`, `d` from key files
- **Multi-Prime RSA** — `n = p*q*r...`
- **PKCS#1 v1.5 Padding Strip** — automatic unpadding

```bash
python3 crypto/rsa_toolkit.py single -n <n> -e <e> -c <c>
python3 crypto/rsa_toolkit.py common-mod -n <n> --e1 <e1> --c1 <c1> --e2 <e2> --c2 <c2>
python3 crypto/rsa_toolkit.py broadcast -e 3 --data pairs.json
python3 crypto/rsa_toolkit.py parse-key key.pem -c <ciphertext>
python3 crypto/rsa_toolkit.py factor -n <n>
python3 crypto/rsa_toolkit.py single -n <n> -e <e> -c <c> --factors-file primes.txt
```

---

#### `xor_bruteforcer.py` — XOR Decryption

Breaks XOR encryption using frequency analysis, crib dragging, and two-time pad attacks.

**Modes:**
- **Single-byte** — brute force all 256 keys, score by English frequency
- **Repeating-key** — auto-guess key length via Hamming distance
- **Crib drag** — drag known plaintext (`flag{`, `the `, etc.) across ciphertext
- **Two-time pad** — XOR two ciphertexts using the same key
- **Known key decrypt** — decrypt with a provided hex key
- **Hex diff** — visual diff between original and decrypted bytes

```bash
python3 crypto/xor_bruteforcer.py ciphertext.bin single
python3 crypto/xor_bruteforcer.py '1b3737...' --hex single --diff
python3 crypto/xor_bruteforcer.py encrypted.bin repeating -o decrypted.txt
python3 crypto/xor_bruteforcer.py encrypted.bin crib --auto
python3 crypto/xor_bruteforcer.py ct1.bin two-time-pad ct2.bin
python3 crypto/xor_bruteforcer.py data.bin decrypt --key-hex 4b455931
```

---

#### `magic_decoder.py` — Recursive Encoding Decoder

A CLI "CyberChef Magic" that recursively decodes nested layers until it finds readable text or a flag.

**Encodings:** Base64, Base32, Base58, Base85, Hex, Decimal, Octal, Binary ASCII, URL, ROT13, ROT47, Morse Code, A1Z26, Unicode Braille, Tap Code

```bash
python3 crypto/magic_decoder.py 'Wm14blEzTmpNak16'
python3 crypto/magic_decoder.py @encoded.txt
python3 crypto/magic_decoder.py '.- -... -.-..' --single      # Morse
python3 crypto/magic_decoder.py '1,2 3,4 5,1' --single        # Tap code
python3 crypto/magic_decoder.py '⠉⠞⠋⠀⠋⠇⠁⠛' --single        # Braille
python3 crypto/magic_decoder.py 'nested_data' -d 15 -o flag.txt
```

---

#### `cipher_solver.py` — Classical Cipher Breaker

Automatically solves historical ciphers commonly found in CTF challenges.

```bash
python3 crypto/cipher_solver.py 'Gur synt vf cvpbPGS{ebg13}' all
python3 crypto/cipher_solver.py 'Khoor Zruog' caesar
python3 crypto/cipher_solver.py 'LXFOPVEFRNHR' vigenere -k LEMON
python3 crypto/cipher_solver.py @challenge.txt all
```

---

### 🌐 Web Exploitation (`web/`)

#### `lfi_scanner.py` — Local File Inclusion Scanner

Tests URL parameters for path traversal and PHP wrapper vulnerabilities.

**Features:**
- Path traversal up to 8 levels deep
- Null-byte injection and double-encoding bypass
- PHP wrappers (`php://filter` base64, rot13, iconv)
- **POST method support**
- **Custom target file wordlist**
- **Windows file targets** (`win.ini`, `boot.ini`)
- **SSH private key and `/proc/self/environ` detection**
- **Custom HTTP headers** for authenticated scanning

```bash
python3 web/lfi_scanner.py 'http://target.com/?page=INJECT'
python3 web/lfi_scanner.py 'http://target.com/view' -p file --method POST
python3 web/lfi_scanner.py 'http://target.com/?f=INJECT' --php
python3 web/lfi_scanner.py 'http://target.com/?f=INJECT' --wordlist targets.txt
python3 web/lfi_scanner.py 'http://target.com/?f=INJECT' --windows
python3 web/lfi_scanner.py 'http://target.com/?f=INJECT' -c 'session=abc' -H 'X-Token: 123'
```

---

#### `sqli_probe.py` — SQL Injection Detector

Detects SQL injection vulnerabilities using multiple techniques.

**Detection Methods:**
- **Error-based** — MySQL, PostgreSQL, SQLite, Oracle, MSSQL error signatures
- **Time-based Blind** — `SLEEP()`, `pg_sleep()`, `WAITFOR DELAY`
- **Boolean-based Blind** — response length difference analysis
- **UNION column count** — automatic column detection (1-29)
- **Header injection** — User-Agent, Referer, X-Forwarded-For, Cookie
- **POST method support**
- Auto-generates `sqlmap` command for full exploitation

```bash
python3 web/sqli_probe.py 'http://target.com/item?id=INJECT'
python3 web/sqli_probe.py 'http://target.com/search' -p query --method POST
python3 web/sqli_probe.py 'http://target.com/' --inject-header user-agent
python3 web/sqli_probe.py 'http://target.com/?id=INJECT' --union --boolean
```

---

### 📡 Network & Packet Analysis (`network/`)

#### `pcap_extractor.py` — PCAP Forensics

Parses `.pcap`/`.pcapng` files to extract actionable intelligence.

**Capabilities:**
- **Protocol statistics** — packet counts, byte totals, IP summary
- **DNS extraction** — queries, responses, and **DNS exfiltration detection** (hex/base64 subdomains)
- **Credential extraction** — HTTP Basic Auth, HTTP forms, FTP `USER`/`PASS`, SMTP AUTH, Telnet
- **HTTP file extraction** — auto-detect content types, save to disk
- **TCP stream following** — reassemble and display text streams
- **ICMP data extraction** — detect ping exfiltration patterns
- **String scanning** — find URLs, emails, and flag patterns across all packets

```bash
python3 network/pcap_extractor.py capture.pcap              # Run all
python3 network/pcap_extractor.py capture.pcap --stats       # Protocol stats only
python3 network/pcap_extractor.py capture.pcap --dns         # DNS only
python3 network/pcap_extractor.py capture.pcap --creds       # Credentials only
python3 network/pcap_extractor.py capture.pcap --streams     # TCP streams
python3 network/pcap_extractor.py capture.pcap --icmp        # ICMP data
python3 network/pcap_extractor.py capture.pcap --strings     # Flags & strings
python3 network/pcap_extractor.py capture.pcap --files -o ./loot/
```

---

#### `usb_hid_parser.py` — USB Keystroke & Mouse Reconstructor

Translates USB HID packets into keystrokes and mouse movements.

**Features:**
- Full keyboard map with **Shift, Caps Lock, Ctrl, Alt** handling
- **F-keys, arrows, PgUp/PgDn, Home/End** recognition
- **Raw event output** mode showing backspaces and all modifiers
- **Dual mouse plot** — click-only drawing + full movement trace
- **Raw hex file input** — works with pre-extracted tshark output
- Uses `tshark` for accurate extraction, falls back to `scapy`

```bash
python3 network/usb_hid_parser.py usb.pcap                  # Both keyboard + mouse
python3 network/usb_hid_parser.py usb.pcap -k --raw          # Raw keyboard events
python3 network/usb_hid_parser.py usb.pcap -m --all           # Dual mouse plot
python3 network/usb_hid_parser.py data.txt --hex -k           # From tshark hex dump
python3 network/usb_hid_parser.py usb.pcap -k -o typed.txt    # Save keystrokes to file
```

---

### 🕵️ Forensics & Steganography (`forensics/`)

#### `metadata_extractor.py` — Exhaustive Metadata Dumper

Powered by `exiftool` for 400+ format support, with a built-in Python fallback.

```bash
python3 forensics/metadata_extractor.py photo.jpg
python3 forensics/metadata_extractor.py firmware.bin --all
python3 forensics/metadata_extractor.py mystery.png --json
python3 forensics/metadata_extractor.py document.pdf --raw
```

---

#### `advanced_zsteg.py` — Advanced LSB Steganography

A pure-Python `zsteg` clone with comprehensive scanning.

**Features:**
- All bit planes (LSB through MSB) across R, G, B, A, RGB, BGR, RGBA channels
- **LSB-first and MSB-first** bit ordering
- **Row-first (xy) and column-first (yx)** pixel ordering
- **20+ file magic signatures** for embedded file detection
- **PNG chunk analysis** — tEXt, zTXt, iTXt with flag detection
- **Auto-extract mode** — saves detected files automatically

```bash
python3 forensics/advanced_zsteg.py stego.png                      # Quick scan
python3 forensics/advanced_zsteg.py stego.png -a                   # All 8 bit planes
python3 forensics/advanced_zsteg.py stego.png --yx                 # Column-first order
python3 forensics/advanced_zsteg.py stego.png --chunks             # PNG chunk analysis
python3 forensics/advanced_zsteg.py stego.png --auto-extract       # Auto-save found files
python3 forensics/advanced_zsteg.py stego.png -e 'RGB,lsb' -o out.bin
```

---

#### `audio_steg.py` — Audio Forensics

Multi-technique audio analysis supporting WAV, MP3, FLAC, and OGG (via ffmpeg).

**Capabilities:**
- **High-res spectrograms** — reveal hidden images/text in frequencies
- **LSB extraction** — bit-level steganography from WAV samples
- **DTMF tone decoder** — convert phone keypad tones to digits
- **Morse code detector** — analyze beep patterns for encoded text
- **Reverse audio** — save reversed copy to check for backward messages
- **Multi-format** — automatic ffmpeg conversion for non-WAV files

```bash
python3 forensics/audio_steg.py audio.wav                    # Run all
python3 forensics/audio_steg.py audio.wav -s --hires         # High-res spectrogram
python3 forensics/audio_steg.py audio.wav -s --cmap gray     # Grayscale spectrogram
python3 forensics/audio_steg.py audio.wav -l --bit 1         # Extract bit 1
python3 forensics/audio_steg.py audio.wav --dtmf             # DTMF tones
python3 forensics/audio_steg.py audio.wav --morse            # Morse code
python3 forensics/audio_steg.py audio.wav --reverse          # Reverse audio
python3 forensics/audio_steg.py audio.mp3 -s                 # Auto-convert MP3
```

---

#### Other Forensics Tools

| Tool | Description | Example |
|------|-------------|---------|
| `file_analyzer.py` | Magic bytes, file type, entropy | `python3 forensics/file_analyzer.py mystery.bin` |
| `strings_finder.py` | String extraction with flag matching | `python3 forensics/strings_finder.py firmware.bin` |
| `hex_viewer.py` | Hex dump with search and highlighting | `python3 forensics/hex_viewer.py data.dat --search "flag"` |
| `steg_basic.py` | Simple LSB extraction, image comparison | `python3 forensics/steg_basic.py lsb image.png` |

---

### 🔓 Password Brute Force (`bruteforce/`)

| Tool | Description | Example |
|------|-------------|---------|
| `hash_cracker.py` | MD5/SHA1/SHA256 wordlist + mutation attacks | `python3 bruteforce/hash_cracker.py <hash> -w rockyou.txt` |
| `archive_cracker.py` | ZIP & PDF password brute force | `python3 bruteforce/archive_cracker.py secret.zip -w wordlist.txt` |
| `wordlist_gen.py` | Custom wordlist with mutations | `python3 bruteforce/wordlist_gen.py --base-words admin,pass --rules full` |
| `jwt_cracker.py` | Decode, brute force HMAC, forge tokens | `python3 bruteforce/jwt_cracker.py decode <token>` |

---

### 🔬 Binary Analysis (`carving/`)

| Tool | Description | Example |
|------|-------------|---------|
| `file_carver.py` | Binwalk alternative — 35+ signatures | `python3 carving/file_carver.py firmware.bin --extract` |
| `entropy_visualizer.py` | Block entropy heatmap (terminal + PNG) | `python3 carving/entropy_visualizer.py firmware.bin --regions` |
| `firmware_analyzer.py` | Header/filesystem/bootloader scanner | `python3 carving/firmware_analyzer.py firmware.bin --all` |

---

## Project Structure

```
ctf-scripts/
├── ctf                          # Interactive TUI launcher (main entry point)
├── README.md
│
├── crypto/                      # Cryptography tools
│   ├── rsa_toolkit.py           #   RSA attacks (Wiener, Fermat, Pollard, FactorDB)
│   ├── xor_bruteforcer.py       #   XOR cracking (freq analysis, crib drag, two-time pad)
│   ├── magic_decoder.py         #   Recursive decoder (15+ encodings incl. Morse, Braille)
│   └── cipher_solver.py         #   Classical ciphers (Caesar, Vigenère, Atbash)
│
├── web/                         # Web exploitation tools
│   ├── lfi_scanner.py           #   LFI scanner (traversal, wrappers, POST, wordlists)
│   └── sqli_probe.py            #   SQLi probe (Error/Time/Boolean/UNION, header inject)
│
├── network/                     # Network forensics tools
│   ├── pcap_extractor.py        #   PCAP analyzer (DNS, creds, streams, ICMP, exfil)
│   └── usb_hid_parser.py        #   USB HID (keyboard + mouse from PCAPs or hex files)
│
├── forensics/                   # Forensics & steganography tools
│   ├── file_analyzer.py         #   File type detection and entropy
│   ├── metadata_extractor.py    #   exiftool-powered metadata (400+ formats)
│   ├── strings_finder.py        #   String extraction with flag matching
│   ├── hex_viewer.py            #   Hex dump with search
│   ├── steg_basic.py            #   Basic LSB and image diff
│   ├── advanced_zsteg.py        #   zsteg clone (all channels, PNG chunks, auto-extract)
│   └── audio_steg.py            #   Audio analysis (spectrogram, DTMF, Morse, reverse)
│
├── bruteforce/                  # Password cracking tools
│   ├── hash_cracker.py          #   Hash cracking with mutations
│   ├── archive_cracker.py       #   ZIP/PDF brute force
│   ├── wordlist_gen.py          #   Custom wordlist generation
│   └── jwt_cracker.py           #   JWT decode and brute force
│
└── carving/                     # Binary analysis tools
    ├── file_carver.py           #   File signature scanning and extraction
    ├── entropy_visualizer.py    #   Entropy heatmaps
    └── firmware_analyzer.py     #   Firmware header/filesystem analysis
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

# 🔍 CTF Forensics Toolkit

A collection of Python scripts for file metadata analysis and forensics challenges in CTF competitions.

## Scripts

| Script | Description |
|--------|-------------|
| `file_analyzer.py` | Magic bytes detection, entropy analysis, hashes, embedded file scanning, trailing data check |
| `metadata_extractor.py` | EXIF (JPEG), PNG text chunks, PDF metadata extraction with auto flag detection |
| `strings_finder.py` | ASCII/UTF-16 string extraction with flag pattern highlighting |
| `hex_viewer.py` | Hex dump with search, highlighting, and colorized output |
| `steg_basic.py` | LSB extraction, bit plane analysis, image comparison, channel separation |

## Requirements

```bash
# Core scripts use Python 3 stdlib only
python3 --version  # 3.7+

# steg_basic.py requires Pillow
pip install Pillow
```

## Quick Reference

### File Analyzer
```bash
python3 file_analyzer.py mystery.bin --all        # Full analysis
python3 file_analyzer.py image.png --entropy       # Entropy heatmap
python3 file_analyzer.py data.bin --embedded       # Find hidden files
python3 file_analyzer.py photo.jpg --trailing      # Check for appended data
```

### Metadata Extractor
```bash
python3 metadata_extractor.py photo.jpg            # EXIF + GPS
python3 metadata_extractor.py image.png            # PNG text chunks
python3 metadata_extractor.py document.pdf         # PDF info + JS detection
python3 metadata_extractor.py file.jpg --json      # JSON output
```

### Strings Finder
```bash
python3 strings_finder.py binary.dat               # All strings (min 4 chars)
python3 strings_finder.py firmware --min-length 8  # Longer strings only
python3 strings_finder.py data --interesting-only   # URLs, base64, creds only
python3 strings_finder.py ctf.bin --flag-format 'picoCTF\{.*?\}'
python3 strings_finder.py data --encoding both     # ASCII + UTF-16
```

### Hex Viewer
```bash
python3 hex_viewer.py file.bin                     # First 512 bytes
python3 hex_viewer.py file --offset 0x100 --length 256
python3 hex_viewer.py file --search "flag{"        # Find ASCII pattern
python3 hex_viewer.py file --search-hex "89504e47" # Find PNG header
cat data | python3 hex_viewer.py -                 # Pipe from stdin
```

### Steganography
```bash
python3 steg_basic.py lsb secret.png               # Extract LSBs from RGB
python3 steg_basic.py lsb img.png --bits 2 --channel R --output hidden.bin
python3 steg_basic.py bitplane image.png --bit 0 --channel G
python3 steg_basic.py compare original.png modified.png --amplify 20
python3 steg_basic.py channels mystery.png --output-dir ./ch
```

## Typical CTF Workflow

```bash
# 1. Identify the file
python3 file_analyzer.py challenge_file --all

# 2. Extract metadata (might contain flag or clue)
python3 metadata_extractor.py challenge_file

# 3. Search for strings & flags
python3 strings_finder.py challenge_file --interesting-only

# 4. Inspect suspicious regions in hex
python3 hex_viewer.py challenge_file --search "flag"

# 5. If it's an image, try steg
python3 steg_basic.py lsb challenge.png --output hidden.txt
python3 steg_basic.py bitplane challenge.png --bit 0
```

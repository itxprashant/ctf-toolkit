#!/usr/bin/env python3
"""
advanced_zsteg.py - CTF Advanced LSB Steganography Extractor

A pure-Python alternative to Ruby's zsteg.
- Multi-channel (R, G, B, A, RGB, BGR, RGBA) scanning
- Multi-bit plane (LSB through MSB) extraction
- LSB-first and MSB-first bit ordering
- Row-first (xy) and column-first (yx) pixel ordering
- Automatic file detection via magic bytes
- PNG chunk analysis (tEXt, zTXt, iTXt, tRNS)
- IDAT raw data anomaly detection
- Auto-extract mode for detected files
"""

import argparse
import sys
import os
import struct
import zlib

try:
    from PIL import Image
except ImportError:
    print("\033[91mError: Pillow not installed.\033[0m")
    print("Please install it: pip install Pillow")
    sys.exit(1)

# ANSI colors
class C:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'

# Magic headers
FILE_MAGICS = [
    (b'\x89PNG\r\n\x1a\n', 'PNG Image'),
    (b'\xff\xd8\xff', 'JPEG Image'),
    (b'PK\x03\x04', 'ZIP Archive'),
    (b'PK\x05\x06', 'ZIP Archive (empty)'),
    (b'%PDF-', 'PDF Document'),
    (b'Rar!\x1a\x07', 'RAR Archive'),
    (b'BZh', 'Bzip2 Archive'),
    (b'\x1f\x8b\x08', 'Gzip Archive'),
    (b'\x7fELF', 'ELF Executable'),
    (b'MZ', 'PE/EXE File'),
    (b'\x50\x4b\x03\x04', 'ZIP/Office Document'),
    (b'\xfd7zXZ\x00', 'XZ Archive'),
    (b'7z\xbc\xaf\x27\x1c', '7-Zip Archive'),
    (b'RIFF', 'RIFF (WAV/AVI)'),
    (b'GIF8', 'GIF Image'),
    (b'BM', 'BMP Image'),
    (b'\x00\x00\x01\x00', 'ICO Image'),
    (b'OggS', 'OGG Audio'),
    (b'fLaC', 'FLAC Audio'),
    (b'ID3', 'MP3 Audio (ID3)'),
    (b'\xff\xfb', 'MP3 Audio'),
    (b'SQLite format 3', 'SQLite Database'),
]

FLAG_PATTERNS = [
    b'flag{', b'FLAG{', b'ctf{', b'CTF{', b'picoCTF{', b'HTB{', b'DUCTF{',
]


def analyze_magic(data: bytes, desc: str, auto_extract: bool = False, out_dir: str = '.'):
    """Check bytes for known file signatures or printable text."""
    if len(data) < 10:
        return False

    # File signatures
    for magic, name in FILE_MAGICS:
        idx = data.find(magic)
        if idx != -1 and idx < 200:
            print(f"  {C.GREEN}▶ {desc:<25}{C.RESET} : {C.RED}{C.BOLD}Embedded file: {name} at offset {idx}{C.RESET}")
            if auto_extract:
                fname = os.path.join(out_dir, f"{desc.replace(',', '_').replace(' ', '_')}.bin")
                with open(fname, 'wb') as f:
                    f.write(data[idx:])
                print(f"    {C.GREEN}Extracted → {fname}{C.RESET}")
            return True

    # Flag patterns
    for pattern in FLAG_PATTERNS:
        idx = data.find(pattern)
        if idx != -1:
            # Read the full flag
            end = data.find(b'}', idx)
            if end != -1:
                flag = data[idx:end+1].decode('utf-8', errors='replace')
                print(f"  {C.RED}{C.BOLD}⚑ {desc:<25}{C.RESET} : {C.RED}{C.BOLD}FLAG: {flag}{C.RESET}")
                return True

    # Mostly printable text
    try:
        text = data[:300].decode('ascii', errors='ignore')
        printable_count = sum(1 for c in text if 32 <= ord(c) <= 126 or c in '\n\r\t')

        if len(text) > 10 and printable_count / len(text) > 0.8:
            clean = "".join(c if (32 <= ord(c) <= 126) else '.' for c in text[:100])
            print(f"  {C.CYAN}▶ {desc:<25}{C.RESET} : {C.YELLOW}{clean}...{C.RESET}")
            return True
    except:
        pass

    return False


def extract_bits(image, channel_order, bit_index, bit_order='lsb', pixel_order='xy'):
    """Extract a specific bit from given channels."""
    width, height = image.size
    pixels = image.load()

    modes = image.mode
    channel_map = {'R': 0, 'G': 1, 'B': 2, 'A': 3, 'L': 0}

    for c in channel_order:
        if c not in channel_map or channel_map[c] >= len(modes):
            return None

    indices = [channel_map[c] for c in channel_order]

    extracted_bits = []

    if pixel_order == 'xy':
        coords = ((x, y) for y in range(height) for x in range(width))
    else:  # yx (column-first)
        coords = ((x, y) for x in range(width) for y in range(height))

    for x, y in coords:
        pixel = pixels[x, y]
        if isinstance(pixel, int):
            pixel = [pixel]

        for idx in indices:
            val = pixel[idx]
            bit = (val >> bit_index) & 1
            extracted_bits.append(bit)

    # Group into bytes
    extracted_bytes = bytearray()
    for i in range(0, len(extracted_bits) - 7, 8):
        byte_bits = extracted_bits[i:i+8]
        if bit_order == 'msb':
            byte_bits = byte_bits[::-1]

        b = 0
        for bit in byte_bits:
            b = (b << 1) | bit
        extracted_bytes.append(b)

    return bytes(extracted_bytes)


# ─── PNG Chunk Analysis ──────────────────────────────────────────────────────

def analyze_png_chunks(filepath):
    """Parse PNG chunks and look for hidden data in tEXt, zTXt, iTXt, etc."""
    print(f"\n{C.CYAN}{C.BOLD}─── PNG Chunk Analysis ────────────────────────────────────────{C.RESET}")

    with open(filepath, 'rb') as f:
        header = f.read(8)
        if header != b'\x89PNG\r\n\x1a\n':
            print(f"  {C.RED}Not a valid PNG file.{C.RESET}")
            return

        chunk_count = 0
        while True:
            length_data = f.read(4)
            if len(length_data) < 4:
                break

            length = struct.unpack('>I', length_data)[0]
            chunk_type = f.read(4)
            chunk_data = f.read(length)
            crc = f.read(4)
            chunk_count += 1

            ct = chunk_type.decode('ascii', errors='replace')
            extra = ''

            if chunk_type == b'tEXt':
                # Null-separated keyword and text
                parts = chunk_data.split(b'\x00', 1)
                keyword = parts[0].decode('utf-8', errors='replace')
                text = parts[1].decode('utf-8', errors='replace') if len(parts) > 1 else ''
                extra = f" → {keyword}: {text[:80]}"
                import re
                flags = re.findall(r'(?:flag|ctf|picoctf|htb)\{[^}]+\}', text, re.IGNORECASE)
                if flags:
                    extra += f" {C.RED}{C.BOLD}⚑ FLAG: {flags[0]}{C.RESET}"

            elif chunk_type == b'zTXt':
                parts = chunk_data.split(b'\x00', 1)
                keyword = parts[0].decode('utf-8', errors='replace')
                if len(parts) > 1 and len(parts[1]) > 1:
                    try:
                        decompressed = zlib.decompress(parts[1][1:]).decode('utf-8', errors='replace')
                        extra = f" → {keyword}: {decompressed[:80]}"
                    except:
                        extra = f" → {keyword}: (compressed, {len(parts[1])} bytes)"

            elif chunk_type == b'iTXt':
                parts = chunk_data.split(b'\x00', 2)
                keyword = parts[0].decode('utf-8', errors='replace')
                extra = f" → {keyword}"

            elif chunk_type == b'IHDR':
                w = struct.unpack('>I', chunk_data[0:4])[0]
                h = struct.unpack('>I', chunk_data[4:8])[0]
                bd = chunk_data[8]
                ct_val = chunk_data[9]
                ct_map = {0: 'Grayscale', 2: 'RGB', 3: 'Indexed', 4: 'Grayscale+Alpha', 6: 'RGBA'}
                extra = f" → {w}x{h}, {bd}-bit, {ct_map.get(ct_val, 'Unknown')}"

            elif chunk_type == b'IDAT':
                extra = f" ({length} bytes)"

            elif chunk_type not in (b'IEND', b'IHDR', b'IDAT', b'PLTE', b'sRGB', b'gAMA', b'pHYs', b'cHRm'):
                # Unknown or unusual chunk
                extra = f" ({length} bytes) {C.YELLOW}[UNUSUAL]{C.RESET}"
                if length < 500:
                    try:
                        text = chunk_data.decode('utf-8', errors='replace')
                        if sum(1 for c in text if c.isprintable()) / max(1, len(text)) > 0.5:
                            extra += f" → {text[:80]}"
                    except:
                        pass

            is_critical = chunk_type[0:1].isupper()
            color = C.BLUE if is_critical else C.DIM
            print(f"  {color}{ct:6s}{C.RESET} {length:8d} bytes{extra}")

    print(f"\n  {C.DIM}Total chunks: {chunk_count}{C.RESET}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF Advanced LSB/MSB Steganography Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s stego.png                          # Quick LSB scan
  %(prog)s stego.png -a                       # Full scan (all 8 bits, both orders)
  %(prog)s stego.png --yx                     # Column-first pixel order
  %(prog)s stego.png --chunks                 # PNG chunk analysis
  %(prog)s stego.png -e 'RGB,lsb' -o out.bin # Extract specific payload
  %(prog)s stego.png --auto-extract           # Auto-save detected files
""")

    parser.add_argument('image', help='Target image (PNG/BMP)')
    parser.add_argument('-a', '--all', action='store_true', help='Test all bits (0-7)')
    parser.add_argument('--yx', action='store_true', help='Also test column-first (yx) pixel order')
    parser.add_argument('-e', '--extract', help='Extract specific payload (e.g., RGB,lsb)')
    parser.add_argument('-o', '--out', default='extracted_payload.bin', help='Output file for --extract')
    parser.add_argument('--chunks', action='store_true', help='Analyze PNG chunks (tEXt, zTXt, etc.)')
    parser.add_argument('--auto-extract', action='store_true', help='Auto-save files detected in bit planes')
    parser.add_argument('--extract-dir', default='./steg_extracted', help='Directory for auto-extracted files')

    args = parser.parse_args()

    try:
        img = Image.open(args.image)
        if img.mode == 'P':
            img = img.convert('RGBA' if 'transparency' in img.info else 'RGB')
    except Exception as e:
        print(f"{C.RED}Error loading image: {e}{C.RESET}")
        sys.exit(1)

    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  Advanced LSB/MSB Analyzer\n{'─' * 60}{C.RESET}")
    print(f"  Image:  {args.image}")
    print(f"  Format: {img.format}  |  Mode: {img.mode}  |  Size: {img.size[0]}×{img.size[1]}")
    print(f"  Pixels: {img.size[0] * img.size[1]:,}\n")

    # PNG chunk analysis
    if args.chunks or args.image.lower().endswith('.png'):
        analyze_png_chunks(args.image)

    # Extract specific payload
    if args.extract:
        print(f"\n{C.CYAN}{C.BOLD}─── Extracting Payload ────────────────────────────────────────{C.RESET}")
        parts = args.extract.split(',')
        channels = parts[0] if len(parts) >= 1 else 'RGB'
        bit_order = parts[1] if len(parts) >= 2 else 'lsb'

        bit_idx = 0
        if bit_order.startswith('b'):
            bit_idx = int(bit_order[1:])
            bit_order = 'lsb'

        data = extract_bits(img, channels, bit_idx, bit_order)
        if data:
            with open(args.out, 'wb') as f:
                f.write(data)
            print(f"  {C.GREEN}▶ Saved {len(data):,} bytes to: {args.out}{C.RESET}")
        else:
            print(f"  {C.RED}Failed to extract.{C.RESET}")
        return

    # Auto-extract setup
    if args.auto_extract:
        os.makedirs(args.extract_dir, exist_ok=True)

    # Channel combos
    if 'A' in img.mode:
        channel_combos = ['R', 'G', 'B', 'A', 'RGB', 'BGR', 'RGBA', 'ABGR']
    elif img.mode == 'L':
        channel_combos = ['L']
    else:
        channel_combos = ['R', 'G', 'B', 'RGB', 'BGR']

    bits_to_test = range(8) if args.all else [0, 1]
    bit_orders = ['lsb', 'msb']
    pixel_orders = ['xy', 'yx'] if args.yx else ['xy']

    total = len(channel_combos) * len(bits_to_test) * len(bit_orders) * len(pixel_orders)
    print(f"  {C.YELLOW}⟳ Scanning {total} bit planes...{C.RESET}\n")

    found_anything = False

    for pixel_order in pixel_orders:
        for bit_idx in bits_to_test:
            for bit_order in bit_orders:
                for channels in channel_combos:
                    desc = f"{channels},b{bit_idx},{bit_order},{pixel_order}"
                    data = extract_bits(img, channels, bit_idx, bit_order, pixel_order)
                    if data:
                        if analyze_magic(data, desc, args.auto_extract, args.extract_dir):
                            found_anything = True

    if not found_anything:
        print(f"  {C.DIM}No hidden files or text found in tested planes.{C.RESET}")
        if not args.all:
            print(f"  {C.DIM}Try: --all (all 8 bits) or --yx (column-first order){C.RESET}")

    print()


if __name__ == '__main__':
    main()

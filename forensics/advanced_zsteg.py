#!/usr/bin/env python3
"""
advanced_zsteg.py - CTF Advanced LSB Steganography Extractor

A pure-Python alternative to Ruby's zsteg.
Explores LSB and MSB data across all color channels (R, G, B, A, RGB, BGR)
in raw bit planes to find hidden files and flags in images.
"""

import argparse
import sys
import struct
from io import BytesIO

# Try importing Pillow
try:
    from PIL import Image
except ImportError:
    print("\033[91mError: Pillow not installed.\033[0m")
    print("Please install it running: pip install Pillow")
    sys.exit(1)

# ANSI colors
class C:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'

# Magic headers to detect files hidden in bits
FILE_MAGICS = [
    (b'\x89PNG', 'PNG Image'),
    (b'\xff\xd8\xff', 'JPEG Image'),
    (b'PK\x03\x04', 'ZIP Archive'),
    (b'%PDF-', 'PDF Document'),
    (b'Rar!\x1a\x07', 'RAR Archive'),
    (b'BZh', 'Bzip2 Archive'),
    (b'\x1f\x8b\x08', 'Gzip Archive'),
    (b'\x7fELF', 'ELF Executable'),
]

def analyze_magic(data: bytes, desc: str):
    """Check bytes for known file signatures or mostly-printable text."""
    if len(data) < 20: return

    # Check magic headers
    for magic, name in FILE_MAGICS:
        idx = data.find(magic)
        if idx != -1 and idx < 100:
            print(f"  {C.GREEN}▶ {desc:<20}{C.RESET} : {C.RED}{C.BOLD}File detected: {name} at offset {idx}{C.RESET}")
            return True

    # Check text
    try:
        text = data[:200].decode('ascii', errors='ignore')
        # Check if text is mostly printable
        printable_count = sum(1 for c in text if 32 <= ord(c) <= 126 or c in '\n\r\t')
        
        if len(text) > 10 and printable_count / len(text) > 0.8:
            # Clean up for display
            clean = "".join(c if (32 <= ord(c) <= 126 and c not in '<>') else '.' for c in text[:80])
            highlight = C.YELLOW
            if 'flag{' in clean.lower() or 'ctf{' in clean.lower():
                highlight = C.RED + C.BOLD
                clean = "⚑ FLAG: " + clean
                
            print(f"  {C.CYAN}▶ {desc:<20}{C.RESET} : {highlight}{clean}...{C.RESET}")
            return True
            
    except Exception:
        pass

    return False

def extract_bits(image, channel_order, bit_index, bit_order='lsb'):
    """Extracts a specific bit from given channels into a byte array."""
    width, height = image.size
    pixels = image.load()
    
    modes = image.mode
    channel_map = {'R': 0, 'G': 1, 'B': 2, 'A': 3, 'L': 0}
    
    # Check if requested channels exist in image
    for c in channel_order:
        if c not in channel_map or channel_map[c] >= len(modes):
            return None
            
    indices = [channel_map[c] for c in channel_order]
    
    extracted_bits = []
    
    # Iterate scanlines (xy order)
    for y in range(height):
        for x in range(width):
            pixel = pixels[x, y]
            if isinstance(pixel, int):
                pixel = [pixel] # Grayscale
                
            for idx in indices:
                val = pixel[idx]
                bit = (val >> bit_index) & 1
                extracted_bits.append(bit)
                
    # Group bits into bytes
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


def extract_specific(image, desc, output_file):
    """Extract payload for a specific string description (like 'RGB,lsb,xy')."""
    print(f"\n{C.CYAN}{C.BOLD}─── Extracting Custom Payload ─────────────────────────────────{C.RESET}")
    parts = desc.split(',')
    if len(parts) >= 2:
        channels, bit_order = parts[0], parts[1]
        
        bit_idx = 0
        if bit_order.startswith('b'): # e.g. b0, b7
            bit_idx = int(bit_order[1:])
            bit_order = 'lsb'
            
        data = extract_bits(image, channels, bit_idx, bit_order)
        if data:
            with open(output_file, 'wb') as f:
                f.write(data)
            print(f"  {C.GREEN}▶ Saved {len(data)} bytes to: {output_file}{C.RESET}")
            return
            
    print(f"  {C.RED}Failed to parse or extract payload descriptor '{desc}'{C.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='CTF Advanced zsteg Python Port',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s stego.png                  # Scan all basic LSB planes
  %(prog)s stego.png -a               # Scan MSB and higher bit planes too
  %(prog)s stego.png -e b1,rgb,lsb,xy # Extract specific payload
""")
    
    parser.add_argument('image', help='Target image (PNG/BMP)')
    parser.add_argument('-a', '--all', action='store_true', help='Test all bits (0-7), not just LSB')
    parser.add_argument('-e', '--extract', help='Extract payload using descriptor (e.g., RGB,lsb) to file')
    parser.add_argument('-o', '--out', default='extracted_payload.bin', help='Output file for --extract (default: extracted_payload.bin)')

    args = parser.parse_args()
    
    try:
        img = Image.open(args.image)
        # Ensure RGB/RGBA instead of paletted for easier math
        if img.mode == 'P':
            img = img.convert('RGBA' if 'transparency' in img.info else 'RGB')
    except Exception as e:
        print(f"{C.RED}Error loading image: {e}{C.RESET}")
        sys.exit(1)

    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  Advanced LSB/MSB Analyzer\n{'─' * 60}{C.RESET}")
    print(f"  Image: {args.image}  |  Format: {img.format}  |  Mode: {img.mode}  |  Size: {img.size[0]}x{img.size[1]}\n")

    if args.extract:
        extract_specific(img, args.extract, args.out)
        return

    # Channels to test
    if 'A' in img.mode:
        channel_combos = ['R', 'G', 'B', 'A', 'RGB', 'BGR', 'RGBA', 'ABGR']
    else:
        channel_combos = ['R', 'G', 'B', 'RGB', 'BGR']

    bits_to_test = range(8) if args.all else [0] # 0 is LSB
    bit_orders = ['lsb', 'msb']

    print(f"  {C.YELLOW}⟳ Scanning {len(channel_combos) * len(bits_to_test) * len(bit_orders)} byte planes...{C.RESET}\n")

    found_anything = False
    
    for bit_idx in bits_to_test:
        for bit_order in bit_orders:
            for channels in channel_combos:
                desc = f"{channels},b{bit_idx},{bit_order},xy"
                
                data = extract_bits(img, channels, bit_idx, bit_order)
                if data:
                    if analyze_magic(data, desc):
                        found_anything = True

    if not found_anything:
        print(f"  {C.DIM}No obvious hidden files or flags found in the tested bit planes.{C.RESET}")
        if not args.all:
            print(f"  {C.DIM}Try running with --all to test higher bit planes.{C.RESET}")
            
    print()

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
file_analyzer.py - CTF File Analysis Toolkit

Identifies file types via magic bytes, calculates entropy, computes hashes,
detects embedded files, and checks for appended data after file trailers.

Usage:
    python3 file_analyzer.py <file> [options]
    python3 file_analyzer.py image.png --entropy --block-size 256
    python3 file_analyzer.py suspicious.bin --embedded --all
"""

import argparse
import hashlib
import math
import os
import struct
import sys

# ─── Magic Bytes Database ────────────────────────────────────────────────────

MAGIC_SIGNATURES = [
    # Images
    (b'\x89PNG\r\n\x1a\n',          'PNG image',               '.png'),
    (b'\xff\xd8\xff',                'JPEG image',              '.jpg'),
    (b'GIF87a',                      'GIF image (87a)',         '.gif'),
    (b'GIF89a',                      'GIF image (89a)',         '.gif'),
    (b'BM',                          'BMP image',               '.bmp'),
    (b'II\x2a\x00',                  'TIFF image (little-endian)', '.tiff'),
    (b'MM\x00\x2a',                  'TIFF image (big-endian)', '.tiff'),
    (b'RIFF',                        'RIFF container (WEBP/AVI/WAV)', '.riff'),

    # Archives
    (b'PK\x03\x04',                  'ZIP archive (or docx/xlsx/jar/apk)', '.zip'),
    (b'PK\x05\x06',                  'ZIP archive (empty)',     '.zip'),
    (b'\x1f\x8b',                    'GZIP archive',            '.gz'),
    (b'BZh',                         'BZIP2 archive',           '.bz2'),
    (b'\xfd7zXZ\x00',               'XZ archive',              '.xz'),
    (b'7z\xbc\xaf\x27\x1c',         '7-Zip archive',           '.7z'),
    (b'Rar!\x1a\x07',               'RAR archive',             '.rar'),

    # Documents
    (b'%PDF',                        'PDF document',            '.pdf'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'MS Office (OLE2) document', '.doc'),

    # Executables
    (b'\x7fELF',                     'ELF executable',          '.elf'),
    (b'MZ',                          'PE/DOS executable',       '.exe'),
    (b'\xfe\xed\xfa\xce',           'Mach-O (32-bit)',         '.macho'),
    (b'\xfe\xed\xfa\xcf',           'Mach-O (64-bit)',         '.macho'),
    (b'\xca\xfe\xba\xbe',           'Java class / Mach-O fat', '.class'),
    (b'\xde\xad\xbe\xef',           'Mach-O fat binary (alt)', '.macho'),

    # Audio/Video
    (b'ID3',                         'MP3 audio (ID3 tag)',     '.mp3'),
    (b'\xff\xfb',                    'MP3 audio',               '.mp3'),
    (b'OggS',                        'OGG container',           '.ogg'),
    (b'fLaC',                        'FLAC audio',              '.flac'),
    (b'\x1a\x45\xdf\xa3',           'Matroska/WebM video',     '.mkv'),

    # Misc
    (b'\x00\x00\x00\x1cftyp',       'MP4/MOV video',           '.mp4'),
    (b'\x00\x00\x00\x20ftyp',       'MP4/MOV video',           '.mp4'),
    (b'SQLite format 3\x00',        'SQLite database',         '.sqlite'),
    (b'\x50\x4b\x03\x04',           'ZIP-based container',     '.zip'),
]

# File trailers for detecting appended data
FILE_TRAILERS = {
    'PNG image':   b'\x00\x00\x00\x00IEND\xae\x42\x60\x82',
    'JPEG image':  b'\xff\xd9',
    'PDF document': b'%%EOF',
    'GIF image (87a)': b'\x3b',
    'GIF image (89a)': b'\x3b',
}

# ANSI colors
class C:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'


def identify_file_type(data):
    """Identify file type from magic bytes."""
    matches = []
    for magic, name, ext in MAGIC_SIGNATURES:
        if data[:len(magic)] == magic:
            matches.append((name, ext, 0))
    return matches


def compute_hashes(filepath):
    """Compute MD5, SHA1, SHA256 of a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def shannon_entropy(data):
    """Calculate Shannon entropy of a byte sequence (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def entropy_analysis(data, block_size=256):
    """Compute per-block entropy. Returns list of (offset, entropy) tuples."""
    results = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        ent = shannon_entropy(block)
        results.append((i, ent))
    return results


def entropy_bar(value, width=30):
    """Create a visual entropy bar."""
    filled = int((value / 8.0) * width)
    if value < 3.0:
        color = C.GREEN
    elif value < 6.0:
        color = C.YELLOW
    elif value < 7.5:
        color = C.MAGENTA
    else:
        color = C.RED
    bar = color + '█' * filled + C.DIM + '░' * (width - filled) + C.RESET
    return bar


def find_embedded_files(data, min_offset=1):
    """Scan for magic bytes at non-zero offsets to find embedded files."""
    found = []
    for magic, name, ext in MAGIC_SIGNATURES:
        offset = min_offset
        while True:
            idx = data.find(magic, offset)
            if idx == -1:
                break
            found.append((idx, name, ext, magic))
            offset = idx + 1
    found.sort(key=lambda x: x[0])
    return found


def check_trailing_data(data, file_type):
    """Check if there's data appended after the file's expected trailer."""
    trailer = FILE_TRAILERS.get(file_type)
    if trailer is None:
        return None, None

    # Search for the last occurrence of the trailer
    idx = data.rfind(trailer)
    if idx == -1:
        return None, None

    trailer_end = idx + len(trailer)
    if trailer_end < len(data):
        extra = data[trailer_end:]
        return trailer_end, extra
    return trailer_end, None


def print_header(text):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 60}")
    print(f"  {text}")
    print(f"{'─' * 60}{C.RESET}")


def print_field(label, value, color=C.GREEN):
    print(f"  {C.BOLD}{label + ':':20s}{C.RESET} {color}{value}{C.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='CTF File Analyzer — magic bytes, entropy, hashes, embedded files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s suspicious.bin
  %(prog)s image.png --entropy --block-size 512
  %(prog)s challenge.dat --embedded
  %(prog)s mystery --all
        """
    )
    parser.add_argument('file', help='File to analyze')
    parser.add_argument('--entropy', '-e', action='store_true',
                        help='Show per-block entropy analysis')
    parser.add_argument('--block-size', '-b', type=int, default=256,
                        help='Block size for entropy analysis (default: 256)')
    parser.add_argument('--embedded', '-E', action='store_true',
                        help='Scan for embedded files')
    parser.add_argument('--trailing', '-t', action='store_true',
                        help='Check for data after file trailer')
    parser.add_argument('--all', '-a', action='store_true',
                        help='Run all analyses')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    if args.all:
        args.entropy = args.embedded = args.trailing = True

    if not os.path.isfile(args.file):
        print(f"{C.RED}Error: '{args.file}' not found or is not a file.{C.RESET}", file=sys.stderr)
        sys.exit(1)

    with open(args.file, 'rb') as f:
        data = f.read()

    file_size = len(data)

    # ── Basic Info ────────────────────────────────────────────────────────
    print_header(f"File Analysis: {os.path.basename(args.file)}")
    print_field('Path', os.path.abspath(args.file), C.BLUE)
    print_field('Size', f'{file_size:,} bytes ({file_size / 1024:.1f} KB)')
    print_field('Overall Entropy', f'{shannon_entropy(data):.4f} / 8.0')

    # ── File Type ─────────────────────────────────────────────────────────
    matches = identify_file_type(data)
    if matches:
        for name, ext, _ in matches:
            print_field('Detected Type', f'{name} ({ext})', C.MAGENTA)
    else:
        print_field('Detected Type', 'Unknown', C.RED)

    # ── Hashes ────────────────────────────────────────────────────────────
    print_header("Hashes")
    md5, sha1, sha256 = compute_hashes(args.file)
    print_field('MD5', md5)
    print_field('SHA1', sha1)
    print_field('SHA256', sha256)

    # ── First/Last Bytes ──────────────────────────────────────────────────
    print_header("Byte Preview")
    hex_head = ' '.join(f'{b:02x}' for b in data[:32])
    hex_tail = ' '.join(f'{b:02x}' for b in data[-32:]) if file_size > 32 else ''
    print(f"  {C.DIM}First 32:{C.RESET} {hex_head}")
    if hex_tail:
        print(f"  {C.DIM}Last  32:{C.RESET} {hex_tail}")

    # ── Entropy Analysis ──────────────────────────────────────────────────
    if args.entropy:
        print_header(f"Entropy Analysis (block size: {args.block_size})")
        blocks = entropy_analysis(data, args.block_size)
        high_entropy_regions = []
        for offset, ent in blocks:
            bar = entropy_bar(ent)
            label = ''
            if ent > 7.5:
                label = f' {C.RED}← encrypted/compressed?{C.RESET}'
                high_entropy_regions.append(offset)
            elif ent < 1.0:
                label = f' {C.GREEN}← mostly null/uniform{C.RESET}'
            print(f"  {C.DIM}0x{offset:08x}{C.RESET} {bar} {ent:.3f}{label}")

        if high_entropy_regions:
            print(f"\n  {C.YELLOW}⚠ {len(high_entropy_regions)} high-entropy blocks detected "
                  f"(possibly encrypted/compressed data){C.RESET}")

    # ── Trailing Data ─────────────────────────────────────────────────────
    if args.trailing and matches:
        print_header("Trailing Data Check")
        for name, ext, _ in matches:
            trailer_end, extra = check_trailing_data(data, name)
            if extra is not None:
                print(f"  {C.RED}⚠ Found {len(extra):,} bytes after {name} trailer "
                      f"at offset 0x{trailer_end:08x}{C.RESET}")
                preview = extra[:64]
                hex_preview = ' '.join(f'{b:02x}' for b in preview)
                ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in preview)
                print(f"  {C.DIM}Hex:   {C.RESET}{hex_preview}")
                print(f"  {C.DIM}ASCII: {C.RESET}{ascii_preview}")
            elif trailer_end is not None:
                print(f"  {C.GREEN}✓ No trailing data after {name} trailer{C.RESET}")
            else:
                print(f"  {C.DIM}No trailer pattern known for {name}{C.RESET}")

    # ── Embedded Files ────────────────────────────────────────────────────
    if args.embedded:
        print_header("Embedded File Scan")
        embedded = find_embedded_files(data)
        if embedded:
            print(f"  {C.YELLOW}Found {len(embedded)} potential embedded file(s):{C.RESET}\n")
            for offset, name, ext, magic in embedded:
                magic_hex = ' '.join(f'{b:02x}' for b in magic[:8])
                print(f"  {C.BOLD}0x{offset:08x}{C.RESET}  {C.MAGENTA}{name}{C.RESET}  "
                      f"{C.DIM}[{magic_hex}]{C.RESET}")
        else:
            print(f"  {C.GREEN}No embedded files detected.{C.RESET}")

    print()


if __name__ == '__main__':
    main()

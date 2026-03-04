#!/usr/bin/env python3
"""
file_carver.py - Pure Python Binwalk Alternative

Scans binary files for embedded files using magic byte signatures,
extracts them, and provides detailed offset maps. No external dependencies.

Usage:
    python3 file_carver.py <file>
    python3 file_carver.py firmware.bin --extract --output-dir carved/
    python3 file_carver.py mystery.dat --scan-only
    python3 file_carver.py blob.bin --min-size 1024
"""

import argparse
import os
import struct
import sys
import zlib

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


# ─── Signature Database ──────────────────────────────────────────────────────
# (magic_bytes, name, extension, header_parser_func_or_None)

def _parse_png_size(data, offset):
    """Calculate PNG file size by walking chunks."""
    pos = offset + 8  # Skip PNG signature
    while pos < len(data) - 12:
        try:
            chunk_len = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            pos += 12 + chunk_len  # length + type + data + CRC
            if chunk_type == b'IEND':
                return pos - offset
        except struct.error:
            break
    return None


def _parse_jpeg_size(data, offset):
    """Calculate JPEG file size by finding EOI marker."""
    pos = offset + 2
    while pos < len(data) - 1:
        if data[pos] == 0xFF:
            marker = data[pos + 1]
            if marker == 0xD9:  # EOI
                return pos + 2 - offset
            elif marker == 0xDA:  # SOS - scan to next marker
                pos += 2
                while pos < len(data) - 1:
                    if data[pos] == 0xFF and data[pos+1] != 0x00 and data[pos+1] != 0xFF:
                        break
                    pos += 1
            elif marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0x01):
                pos += 2
            elif marker == 0xFF:
                pos += 1
            else:
                try:
                    seg_len = struct.unpack('>H', data[pos+2:pos+4])[0]
                    pos += 2 + seg_len
                except struct.error:
                    break
        else:
            pos += 1
    return None


def _parse_zip_size(data, offset):
    """Estimate ZIP size by finding End of Central Directory."""
    # Search for EOCD signature
    search_start = offset
    eocd_sig = b'PK\x05\x06'
    idx = data.find(eocd_sig, search_start)
    while idx != -1:
        try:
            # EOCD is 22 bytes minimum + comment
            comment_len = struct.unpack('<H', data[idx+20:idx+22])[0]
            return idx + 22 + comment_len - offset
        except struct.error:
            pass
        idx = data.find(eocd_sig, idx + 1)
    return None


def _parse_gzip_size(data, offset):
    """Decompress gzip to determine compressed size."""
    try:
        # Try decompressing to find where it ends
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        pos = offset
        chunk_size = 4096
        while pos < len(data):
            chunk = data[pos:pos + chunk_size]
            if not chunk:
                break
            try:
                dec.decompress(chunk)
                pos += chunk_size
            except zlib.error:
                # Binary search for exact end
                for i in range(len(chunk)):
                    try:
                        dec2 = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        dec2.decompress(data[offset:pos + i])
                        dec2.flush()
                        return pos + i - offset
                    except zlib.error:
                        continue
                break
        return pos - offset
    except Exception:
        return None


def _parse_elf_size(data, offset):
    """Parse ELF header to determine file size."""
    try:
        ei_class = data[offset + 4]
        if ei_class == 1:  # 32-bit
            fmt = '<'
            e_shoff = struct.unpack(fmt + 'I', data[offset+32:offset+36])[0]
            e_shentsize = struct.unpack(fmt + 'H', data[offset+46:offset+48])[0]
            e_shnum = struct.unpack(fmt + 'H', data[offset+48:offset+50])[0]
        elif ei_class == 2:  # 64-bit
            fmt = '<'
            e_shoff = struct.unpack(fmt + 'Q', data[offset+40:offset+48])[0]
            e_shentsize = struct.unpack(fmt + 'H', data[offset+58:offset+60])[0]
            e_shnum = struct.unpack(fmt + 'H', data[offset+60:offset+62])[0]
        else:
            return None
        return e_shoff + (e_shentsize * e_shnum)
    except (struct.error, IndexError):
        return None


# Signature definitions: (magic, name, extension, size_parser, min_gap)
SIGNATURES = [
    # Images
    (b'\x89PNG\r\n\x1a\n',          'PNG image',           'png',   _parse_png_size,   0),
    (b'\xff\xd8\xff',                'JPEG image',          'jpg',   _parse_jpeg_size,  0),
    (b'GIF87a',                      'GIF image (87a)',     'gif',   None,              0),
    (b'GIF89a',                      'GIF image (89a)',     'gif',   None,              0),
    (b'BM',                          'BMP image',           'bmp',   None,              0),
    (b'RIFF',                        'RIFF (AVI/WAV/WEBP)', 'riff',  None,              0),

    # Archives
    (b'PK\x03\x04',                  'ZIP archive',         'zip',   _parse_zip_size,   0),
    (b'\x1f\x8b',                    'GZIP archive',        'gz',    _parse_gzip_size,  0),
    (b'BZh',                         'BZIP2 archive',       'bz2',   None,              0),
    (b'\xfd7zXZ\x00',               'XZ archive',          'xz',    None,              0),
    (b'7z\xbc\xaf\x27\x1c',         '7-Zip archive',       '7z',    None,              0),
    (b'Rar!\x1a\x07',               'RAR archive',         'rar',   None,              0),

    # Documents
    (b'%PDF',                        'PDF document',        'pdf',   None,              0),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'OLE2 (DOC/XLS)', 'doc', None,              0),

    # Executables
    (b'\x7fELF',                     'ELF executable',      'elf',   _parse_elf_size,   0),
    (b'MZ',                          'PE/DOS executable',   'exe',   None,              4),

    # Firmware / Filesystems
    (b'hsqs',                        'SquashFS (LE)',        'squashfs', None,           0),
    (b'sqsh',                        'SquashFS (BE)',        'squashfs', None,           0),
    (b'\x68\x73\x71\x73',           'SquashFS',            'squashfs', None,           0),
    (b'\x27\x05\x19\x56',           'U-Boot uImage',       'uimage', None,             0),
    (b'UBI#',                        'UBI image',           'ubi',   None,              0),
    (b'\x85\x19\x01\x20',           'JFFS2 (LE)',          'jffs2', None,              0),
    (b'\x20\x01\x19\x85',           'JFFS2 (BE)',          'jffs2', None,              0),
    (b'\x45\x3d\xcd\x28',           'CramFS (LE)',         'cramfs', None,             0),
    (b'\x28\xcd\x3d\x45',           'CramFS (BE)',         'cramfs', None,             0),
    (b'\xd0\x0d\xfe\xed',           'Device Tree blob',    'dtb',   None,              0),

    # Crypto / Certificates
    (b'-----BEGIN',                  'PEM certificate/key', 'pem',   None,              0),
    (b'\x30\x82',                    'DER certificate',     'der',   None,              4),

    # Audio/Video
    (b'ID3',                         'MP3 audio (ID3)',     'mp3',   None,              0),
    (b'OggS',                        'OGG audio',           'ogg',   None,              0),
    (b'fLaC',                        'FLAC audio',          'flac',  None,              0),
    (b'\x1a\x45\xdf\xa3',           'Matroska/WebM',       'mkv',   None,              0),

    # Database
    (b'SQLite format 3\x00',        'SQLite database',     'sqlite', None,             0),

    # Scripts / Text
    (b'#!/bin/sh',                   'Shell script',        'sh',    None,              0),
    (b'#!/bin/bash',                 'Bash script',         'sh',    None,              0),
    (b'#!/usr/bin/env python',       'Python script',       'py',    None,              0),
    (b'#!/usr/bin/python',           'Python script',       'py',    None,              0),
    (b'<?xml',                       'XML document',        'xml',   None,              4),
    (b'<!DOCTYPE html',              'HTML document',       'html',  None,              0),
    (b'<html',                       'HTML document',       'html',  None,              4),
]


def print_header(text):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 70}")
    print(f"  {text}")
    print(f"{'─' * 70}{C.RESET}")


def print_field(label, value, color=C.GREEN):
    print(f"  {C.BOLD}{label + ':':20s}{C.RESET} {color}{value}{C.RESET}")


# ─── Scanner ─────────────────────────────────────────────────────────────────

def scan_file(data, min_size=32):
    """Scan file for all embedded file signatures."""
    results = []

    for magic, name, ext, size_parser, min_gap in SIGNATURES:
        offset = 0
        while offset < len(data):
            idx = data.find(magic, offset)
            if idx == -1:
                break

            # Skip if too close to a previous find of same type
            if min_gap > 0 and results:
                too_close = False
                for r in results:
                    if r['name'] == name and abs(r['offset'] - idx) < min_gap:
                        too_close = True
                        break
                if too_close:
                    offset = idx + 1
                    continue

            # Try to determine size
            size = None
            if size_parser:
                size = size_parser(data, idx)

            if size is None:
                # Estimate by finding next signature or end of file
                size = len(data) - idx

            # Skip tiny matches
            if size < min_size:
                offset = idx + 1
                continue

            results.append({
                'offset': idx,
                'name': name,
                'extension': ext,
                'size': size,
                'size_known': size_parser is not None,
                'magic': magic[:8],
            })

            offset = idx + len(magic)

    # Sort by offset
    results.sort(key=lambda x: x['offset'])
    return results


# ─── Extractor ────────────────────────────────────────────────────────────────

def extract_files(data, results, output_dir):
    """Extract embedded files to output directory."""
    os.makedirs(output_dir, exist_ok=True)
    extracted = []

    for i, result in enumerate(results):
        offset = result['offset']
        size = result['size']
        ext = result['extension']
        name = result['name']

        # Clamp size to available data
        actual_size = min(size, len(data) - offset)
        carved_data = data[offset:offset + actual_size]

        filename = f"{i:04d}_{offset:#010x}.{ext}"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, 'wb') as f:
            f.write(carved_data)

        extracted.append({
            'filename': filename,
            'path': filepath,
            'offset': offset,
            'size': actual_size,
            'name': name,
        })

    return extracted


# ─── Display ──────────────────────────────────────────────────────────────────

def format_size(size):
    """Format byte size to human readable."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.1f} GB"


def print_offset_map(data, results):
    """Print a visual map of file contents."""
    if not results:
        return

    total = len(data)
    width = 60

    print(f"\n  {C.BOLD}Offset Map:{C.RESET}")
    print(f"  {C.DIM}{'─' * (width + 20)}{C.RESET}")

    colors = [C.GREEN, C.YELLOW, C.MAGENTA, C.CYAN, C.BLUE, C.RED]

    for i, r in enumerate(results):
        color = colors[i % len(colors)]
        start_pct = r['offset'] / total
        end_pct = min((r['offset'] + r['size']) / total, 1.0)
        bar_start = int(start_pct * width)
        bar_end = max(int(end_pct * width), bar_start + 1)

        bar = ' ' * bar_start + color + '█' * (bar_end - bar_start) + C.RESET + ' ' * (width - bar_end)
        print(f"  {C.DIM}0x{r['offset']:08x}{C.RESET} [{bar}] {color}{r['name']}{C.RESET}")

    print(f"  {C.DIM}{'─' * (width + 20)}{C.RESET}")
    print(f"  {C.DIM}0x00000000{' ' * (width - 18)}0x{total:08x}{C.RESET}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF File Carver — scan and extract embedded files (pure Python binwalk alternative)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s firmware.bin                          # Scan for embedded files
  %(prog)s firmware.bin --extract                # Scan and extract
  %(prog)s blob.dat --extract --output-dir out/  # Extract to specific dir
  %(prog)s mystery --scan-only                   # Only show scan results
  %(prog)s image.bin --min-size 1024             # Skip small matches
  %(prog)s data.bin --json                       # JSON output

Detected formats:
  Images:      PNG, JPEG, GIF, BMP, WEBP
  Archives:    ZIP, GZIP, BZIP2, XZ, 7z, RAR
  Documents:   PDF, OLE2 (DOC/XLS)
  Executables: ELF, PE/DOS
  Firmware:    SquashFS, U-Boot, UBI, JFFS2, CramFS, DTB
  Audio:       MP3, OGG, FLAC, MKV/WebM
  Other:       SQLite, PEM certs, shell/python scripts
        """
    )
    parser.add_argument('file', help='File to scan')
    parser.add_argument('--extract', '-e', action='store_true',
                        help='Extract embedded files')
    parser.add_argument('--output-dir', '-o', type=str, default=None,
                        help='Output directory for extracted files (default: <filename>_carved/)')
    parser.add_argument('--scan-only', '-s', action='store_true',
                        help='Only show scan results, don\'t extract')
    parser.add_argument('--min-size', '-m', type=int, default=32,
                        help='Minimum file size to report (default: 32 bytes)')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output results as JSON')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    if not os.path.isfile(args.file):
        print(f"{C.RED}Error: '{args.file}' not found.{C.RESET}", file=sys.stderr)
        sys.exit(1)

    with open(args.file, 'rb') as f:
        data = f.read()

    file_size = len(data)

    # Scan
    results = scan_file(data, args.min_size)

    if args.json:
        import json
        output = {
            'file': os.path.abspath(args.file),
            'file_size': file_size,
            'results': [{
                'offset': r['offset'],
                'offset_hex': f"0x{r['offset']:08x}",
                'type': r['name'],
                'extension': r['extension'],
                'size': r['size'],
                'size_exact': r['size_known'],
            } for r in results]
        }
        print(json.dumps(output, indent=2))
        return

    print_header(f"File Carver: {os.path.basename(args.file)}")
    print_field('File Size', f'{file_size:,} bytes ({format_size(file_size)})')
    print_field('Signatures Found', str(len(results)))

    if not results:
        print(f"\n  {C.YELLOW}No embedded files detected.{C.RESET}\n")
        return

    # Results table
    print(f"\n  {C.BOLD}{'Offset':>12s}  {'Type':<25s}  {'Size':>12s}  {'Exact':>5s}{C.RESET}")
    print(f"  {C.DIM}{'─' * 60}{C.RESET}")

    for r in results:
        exact = f"{C.GREEN}✓{C.RESET}" if r['size_known'] else f"{C.DIM}~{C.RESET}"
        size_str = format_size(r['size'])

        # Highlight first match (likely the main file)
        if r['offset'] == 0:
            type_str = f"{C.BLUE}{r['name']}{C.RESET}"
        else:
            type_str = f"{C.MAGENTA}{r['name']}{C.RESET}"

        print(f"  {C.DIM}0x{r['offset']:08x}{C.RESET}  {type_str:<35s}  "
              f"{C.GREEN}{size_str:>12s}{C.RESET}  {exact}")

    # Offset map
    print_offset_map(data, results)

    # Extract
    if args.extract and not args.scan_only:
        output_dir = args.output_dir or f"{os.path.splitext(args.file)[0]}_carved"
        print_header("Extracting Files")
        extracted = extract_files(data, results, output_dir)

        for e in extracted:
            print(f"  {C.GREEN}✓{C.RESET} {e['filename']}  "
                  f"{C.DIM}({e['name']}, {format_size(e['size'])}){C.RESET}")

        print(f"\n  {C.GREEN}Extracted {len(extracted)} files to: {output_dir}/{C.RESET}")
    elif not args.scan_only and len(results) > 1:
        print(f"\n  {C.DIM}Use --extract to carve out embedded files{C.RESET}")

    print()


if __name__ == '__main__':
    main()

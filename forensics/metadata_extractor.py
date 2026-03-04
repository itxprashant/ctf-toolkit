#!/usr/bin/env python3
"""
metadata_extractor.py - CTF Metadata Extraction Toolkit

Uses exiftool to dump ALL metadata from any file format.
Falls back to a built-in parser if exiftool is not installed.

Supports: JPEG, PNG, PDF, TIFF, GIF, BMP, WEBP, MP3, MP4, MKV,
          OLE2 (DOC/XLS), ZIP, ELF, and hundreds more via exiftool.

Usage:
    python3 metadata_extractor.py <file>
    python3 metadata_extractor.py photo.jpg --all
    python3 metadata_extractor.py document.pdf --json
"""

import argparse
import datetime
import json
import os
import re
import shutil
import struct
import subprocess
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


# ─── Helpers ──────────────────────────────────────────────────────────────────

def print_header(text):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 60}")
    print(f"  {text}")
    print(f"{'─' * 60}{C.RESET}")


def print_field(label, value, color=C.GREEN):
    print(f"  {C.BOLD}{label + ':':30s}{C.RESET} {color}{value}{C.RESET}")


def check_flags(value):
    """Check if a value looks like it could contain a CTF flag."""
    flag_patterns = [
        r'flag\{.*?\}', r'ctf\{.*?\}', r'FLAG\{.*?\}', r'CTF\{.*?\}',
        r'picoCTF\{.*?\}', r'HTB\{.*?\}', r'DUCTF\{.*?\}',
        r'[A-Za-z0-9+/]{30,}={0,2}',  # Base64
    ]
    for pattern in flag_patterns:
        if re.search(pattern, str(value)):
            print(f"  {C.RED}{C.BOLD}  ⚑ POSSIBLE FLAG DETECTED!{C.RESET}")
            return True
    return False


# ─── Interesting tag names for CTF highlighting ──────────────────────────────

INTERESTING_TAGS = {
    'comment', 'usercomment', 'imagedescription', 'description',
    'xpcomment', 'xptitle', 'xpkeywords', 'xpsubject', 'xpauthor',
    'artist', 'copyright', 'author', 'subject', 'title', 'keywords',
    'software', 'creator', 'producer', 'cameraownername',
    'imageuniqueid', 'serialnumber', 'bodyserial', 'lensserial',
    'documentname', 'pagename', 'hostcomputer', 'make', 'model',
    'profiledescription', 'warning',
}

GPS_TAGS = {'gpslatitude', 'gpslongitude', 'gpsaltitude', 'gpsposition'}

WARNING_TAGS = {'warning', 'error'}


# ─── Exiftool Backend ────────────────────────────────────────────────────────

def has_exiftool():
    """Check if exiftool is available on the system."""
    return shutil.which('exiftool') is not None


def run_exiftool(filepath, extra_args=None):
    """Run exiftool and return parsed tag dict."""
    cmd = [
        'exiftool',
        '-json',            # JSON output
        '-G1',              # Group names (e.g., EXIF, IPTC, XMP)
        '-s',               # Short tag names
        '-n',               # Numeric values (avoid localized strings)
        '-struct',          # Structured output for complex tags
        '-charset', 'UTF8',
    ]
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(filepath)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if data and isinstance(data, list):
                return data[0]
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    return None


def run_exiftool_text(filepath, extra_args=None):
    """Run exiftool in text mode for human-readable output."""
    cmd = [
        'exiftool',
        '-G1',              # Group names
        '-a',               # Allow duplicates
        '-u',               # Show unknown tags
        '-charset', 'UTF8',
    ]
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(filepath)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout if result.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def extract_with_exiftool(filepath, show_all=False, json_mode=False):
    """Extract all metadata using exiftool."""

    if json_mode:
        args = ['-a', '-u']  # All tags, including unknown
        if show_all:
            args.extend(['-ee', '-api', 'LargeFileSupport=1'])
        data = run_exiftool(filepath, args)
        return data

    # ── Text mode with colored output ─────────────────────────────────────
    args = ['-a', '-u']
    if show_all:
        args.extend(['-ee', '-api', 'LargeFileSupport=1'])

    data = run_exiftool(filepath, args)
    if not data:
        print(f"  {C.RED}exiftool returned no data.{C.RESET}")
        return None

    # Group tags by their group name
    groups = {}
    for key, value in data.items():
        if key == 'SourceFile':
            continue
        # Key format from -G1 -s: "Group:TagName"
        if ':' in key:
            group, tag = key.split(':', 1)
        else:
            group, tag = 'Other', key
        if group not in groups:
            groups[group] = []
        groups[group].append((tag, value))

    # Display by group
    for group in sorted(groups.keys()):
        tags = groups[group]
        print_header(f"{group}")

        for tag, value in tags:
            tag_lower = tag.lower()
            val_str = str(value)

            # Choose color based on tag type
            if tag_lower in WARNING_TAGS:
                color = C.RED
            elif tag_lower in GPS_TAGS:
                color = C.YELLOW
            elif tag_lower in INTERESTING_TAGS:
                color = C.YELLOW
            elif isinstance(value, str) and len(value) > 100:
                color = C.DIM  # Long binary/encoded data
            else:
                color = C.GREEN

            # Truncate very long values
            if len(val_str) > 200:
                val_str = val_str[:200] + f'... ({len(str(value))} chars)'

            print_field(tag, val_str, color)
            check_flags(val_str)

    # ── GPS coordinate helper ─────────────────────────────────────────────
    lat = data.get('Composite:GPSLatitude') or data.get('EXIF:GPSLatitude')
    lon = data.get('Composite:GPSLongitude') or data.get('EXIF:GPSLongitude')
    if lat is not None and lon is not None:
        try:
            lat_f = float(lat)
            lon_f = float(lon)
            print_header("GPS Quick Link")
            print_field('Coordinates', f'{lat_f:.6f}, {lon_f:.6f}', C.YELLOW)
            print_field('Google Maps',
                        f'https://www.google.com/maps?q={lat_f},{lon_f}', C.YELLOW)
        except (ValueError, TypeError):
            pass

    return data


# ─── Built-in Fallback (no exiftool) ─────────────────────────────────────────

def extract_file_metadata(filepath):
    """Extract OS-level file metadata."""
    print_header(f"File Metadata: {os.path.basename(filepath)}")

    st = os.stat(filepath)
    print_field('Path', os.path.abspath(filepath), C.BLUE)
    print_field('Size', f'{st.st_size:,} bytes ({st.st_size / 1024:.1f} KB)')

    mtime = datetime.datetime.fromtimestamp(st.st_mtime)
    atime = datetime.datetime.fromtimestamp(st.st_atime)
    ctime = datetime.datetime.fromtimestamp(st.st_ctime)
    print_field('Modified', mtime.strftime('%Y-%m-%d %H:%M:%S'))
    print_field('Accessed', atime.strftime('%Y-%m-%d %H:%M:%S'))
    print_field('Created/Changed', ctime.strftime('%Y-%m-%d %H:%M:%S'))
    print_field('Permissions', oct(st.st_mode)[-3:])
    print_field('Owner UID/GID', f'{st.st_uid}/{st.st_gid}')


def fallback_extract(filepath, data):
    """Basic metadata extraction without exiftool."""
    print(f"\n  {C.YELLOW}⚠ exiftool not found — using built-in parser (limited).{C.RESET}")
    print(f"  {C.DIM}Install: sudo apt install libimage-exiftool-perl{C.RESET}\n")

    extract_file_metadata(filepath)
    extracted = False

    # JPEG — basic EXIF scan
    if data[:2] == b'\xff\xd8':
        extracted = True
        print_header("JPEG Analysis")
        print_field('Format', 'JPEG image')

        # Look for EXIF APP1
        offset = 2
        while offset < len(data) - 4:
            if data[offset] != 0xff:
                break
            marker = data[offset + 1]
            length = struct.unpack('>H', data[offset + 2:offset + 4])[0]

            if marker == 0xe1:  # APP1
                app_data = data[offset + 4:offset + 2 + length]
                if app_data[:4] == b'Exif':
                    print_field('EXIF Data', f'Found at offset 0x{offset:x} ({length} bytes)')
                elif app_data[:28] == b'http://ns.adobe.com/xap/1.0/':
                    print_field('XMP Data', f'Found at offset 0x{offset:x} ({length} bytes)')
            elif marker == 0xfe:  # COM (comment)
                comment = data[offset + 4:offset + 2 + length]
                try:
                    comment_str = comment.decode('utf-8', errors='replace')
                    print_field('JPEG Comment', comment_str, C.YELLOW)
                    check_flags(comment_str)
                except Exception:
                    pass
            elif marker == 0xe0:  # APP0 JFIF
                print_field('JFIF', f'Found at offset 0x{offset:x}')
            elif marker in (0xDA, 0xD9):
                break

            offset += 2 + length

    # PNG — text chunks
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        extracted = True
        print_header("PNG Analysis")
        offset = 8
        while offset < len(data) - 12:
            try:
                length = struct.unpack('>I', data[offset:offset + 4])[0]
                chunk_type = data[offset + 4:offset + 8].decode('ascii')
                chunk_data = data[offset + 8:offset + 8 + length]
            except Exception:
                break

            if chunk_type == 'IHDR' and length >= 13:
                w, h = struct.unpack('>II', chunk_data[:8])
                print_field('Dimensions', f'{w} x {h}')
                print_field('Bit Depth', str(chunk_data[8]))
                ct = {0:'Grayscale', 2:'RGB', 3:'Indexed', 4:'Gray+A', 6:'RGBA'}
                print_field('Color Type', ct.get(chunk_data[9], str(chunk_data[9])))

            elif chunk_type == 'tEXt':
                null_idx = chunk_data.find(b'\x00')
                if null_idx != -1:
                    key = chunk_data[:null_idx].decode('latin-1')
                    val = chunk_data[null_idx + 1:].decode('latin-1')
                    print_field(f'tEXt:{key}', val, C.YELLOW)
                    check_flags(val)

            elif chunk_type == 'zTXt':
                null_idx = chunk_data.find(b'\x00')
                if null_idx != -1:
                    key = chunk_data[:null_idx].decode('latin-1')
                    try:
                        val = zlib.decompress(chunk_data[null_idx + 2:]).decode('latin-1')
                        print_field(f'zTXt:{key}', val, C.YELLOW)
                        check_flags(val)
                    except zlib.error:
                        print_field(f'zTXt:{key}', '<decompression failed>', C.RED)

            elif chunk_type == 'iTXt':
                null_idx = chunk_data.find(b'\x00')
                if null_idx != -1:
                    key = chunk_data[:null_idx].decode('utf-8', errors='replace')
                    rest = chunk_data[null_idx + 3:]  # skip comp flag, method
                    for _ in range(2):
                        ni = rest.find(b'\x00')
                        rest = rest[ni + 1:] if ni != -1 else rest
                    val = rest.decode('utf-8', errors='replace')
                    print_field(f'iTXt:{key}', val, C.YELLOW)
                    check_flags(val)

            elif chunk_type == 'tIME' and length == 7:
                year = struct.unpack('>H', chunk_data[:2])[0]
                month, day, hour, minute, second = chunk_data[2:7]
                ts = f'{year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}'
                print_field('Last Modified', ts)

            offset += 12 + length

    # PDF — info dict
    if data[:5] == b'%PDF-':
        extracted = True
        text = data.decode('latin-1', errors='replace')
        print_header("PDF Analysis")
        print_field('Version', text[:text.find('\n')].strip())

        for field in ['Title', 'Author', 'Subject', 'Keywords', 'Creator',
                       'Producer', 'CreationDate', 'ModDate']:
            match = re.search(rf'/{field}\s*\(([^)]*)\)', text)
            if match:
                print_field(field, match.group(1), C.YELLOW)
                check_flags(match.group(1))

        if '/JavaScript' in text or '/JS' in text:
            print_field('⚠ JavaScript', 'Contains embedded JavaScript!', C.RED)
        if '/EmbeddedFile' in text:
            print_field('⚠ Embedded Files', 'Contains embedded files!', C.RED)

    if not extracted:
        print(f"\n  {C.YELLOW}No format-specific metadata extracted.{C.RESET}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF Metadata Extractor — powered by exiftool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s photo.jpg              # All metadata
  %(prog)s photo.jpg --all        # Deep scan (embedded files, large files)
  %(prog)s mystery.bin --json     # JSON output
  %(prog)s document.pdf           # PDF metadata + warnings

Powered by exiftool when available (recommended).
Falls back to built-in parser if exiftool is not installed.
Install: sudo apt install libimage-exiftool-perl
        """
    )
    parser.add_argument('file', help='File to extract metadata from')
    parser.add_argument('--all', '-a', action='store_true',
                        help='Deep scan (embedded files, unknown tags)')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output as JSON')
    parser.add_argument('--raw', '-r', action='store_true',
                        help='Show raw exiftool text output')
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

    # ── Raw mode ──────────────────────────────────────────────────────────
    if args.raw:
        if not has_exiftool():
            print(f"{C.RED}Error: exiftool not installed.{C.RESET}", file=sys.stderr)
            sys.exit(1)
        extra = ['-a', '-u']
        if args.all:
            extra.extend(['-ee', '-api', 'LargeFileSupport=1'])
        output = run_exiftool_text(args.file, extra)
        if output:
            print(output)
        return

    # ── JSON mode ─────────────────────────────────────────────────────────
    if args.json:
        if has_exiftool():
            data = extract_with_exiftool(args.file, show_all=args.all, json_mode=True)
            if data:
                print(json.dumps(data, indent=2, default=str))
                return
        # Fallback JSON
        with open(args.file, 'rb') as f:
            file_data = f.read()
        st = os.stat(args.file)
        print(json.dumps({
            'file': args.file,
            'size': st.st_size,
            'modified': datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
            'note': 'Install exiftool for full metadata: sudo apt install libimage-exiftool-perl',
        }, indent=2))
        return

    # ── Normal mode ───────────────────────────────────────────────────────
    if has_exiftool():
        version_cmd = subprocess.run(['exiftool', '-ver'], capture_output=True, text=True)
        ver = version_cmd.stdout.strip() if version_cmd.returncode == 0 else '?'
        print(f"\n  {C.DIM}Using exiftool v{ver}{C.RESET}")

        extract_with_exiftool(args.file, show_all=args.all)
    else:
        with open(args.file, 'rb') as f:
            file_data = f.read()
        fallback_extract(args.file, file_data)

    print()


if __name__ == '__main__':
    main()

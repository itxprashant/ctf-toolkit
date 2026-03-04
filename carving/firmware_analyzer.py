#!/usr/bin/env python3
"""
firmware_analyzer.py - CTF Firmware Analysis Tool

Identifies firmware structures: bootloaders, headers, filesystem types,
kernel images, and configuration data. Useful for IoT/embedded CTF challenges.

Usage:
    python3 firmware_analyzer.py <file>
    python3 firmware_analyzer.py router_firmware.bin --all
    python3 firmware_analyzer.py iot_dump.bin --strings --flag-format 'flag{.*}'
"""

import argparse
import math
import os
import re
import struct
import sys

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


def print_header(text):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 70}")
    print(f"  {text}")
    print(f"{'─' * 70}{C.RESET}")


def print_field(label, value, color=C.GREEN):
    print(f"  {C.BOLD}{label + ':':22s}{C.RESET} {color}{value}{C.RESET}")


def format_size(size):
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"


# ─── Firmware Header Detection ───────────────────────────────────────────────

FIRMWARE_HEADERS = [
    # Bootloaders
    {
        'name': 'U-Boot Image (uImage)',
        'magic': b'\x27\x05\x19\x56',
        'parser': '_parse_uboot',
    },
    {
        'name': 'U-Boot Boot Script',
        'magic': b'\x27\x05\x19\x56',
        'parser': None,
    },
    {
        'name': 'ARM Exception Vector',
        'magic': b'\x00\x00\x00\xea',
        'parser': None,
    },

    # Filesystems
    {
        'name': 'SquashFS (Little Endian)',
        'magic': b'hsqs',
        'parser': '_parse_squashfs',
    },
    {
        'name': 'SquashFS (Big Endian)',
        'magic': b'sqsh',
        'parser': '_parse_squashfs_be',
    },
    {
        'name': 'CramFS (Little Endian)',
        'magic': b'\x45\x3d\xcd\x28',
        'parser': '_parse_cramfs',
    },
    {
        'name': 'CramFS (Big Endian)',
        'magic': b'\x28\xcd\x3d\x45',
        'parser': None,
    },
    {
        'name': 'JFFS2 (Little Endian)',
        'magic': b'\x85\x19',
        'parser': None,
    },
    {
        'name': 'JFFS2 (Big Endian)',
        'magic': b'\x19\x85',
        'parser': None,
    },
    {
        'name': 'UBI Erase Count',
        'magic': b'UBI#',
        'parser': None,
    },
    {
        'name': 'UBIFS',
        'magic': b'\x31\x18\x10\x06',
        'parser': None,
    },
    {
        'name': 'EXT filesystem',
        'magic': b'\x53\xef',
        'parser': None,
        'offset': 0x438,  # Superblock magic at offset 0x438
    },
    {
        'name': 'YAFFS',
        'magic': b'\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff',
        'parser': None,
    },

    # Kernel / OS
    {
        'name': 'Linux Kernel (ARM zImage)',
        'magic': b'\x00\x00\xa0\xe1',
        'parser': None,
    },
    {
        'name': 'Linux Kernel Image',
        'magic': b'Linux version',
        'parser': '_parse_linux_version',
    },
    {
        'name': 'Device Tree Blob',
        'magic': b'\xd0\x0d\xfe\xed',
        'parser': '_parse_dtb',
    },

    # Compression
    {
        'name': 'LZMA compressed',
        'magic': b'\x5d\x00\x00',
        'parser': None,
    },
    {
        'name': 'LZO compressed',
        'magic': b'\x89\x4c\x5a\x4f',
        'parser': None,
    },
    {
        'name': 'Zstandard compressed',
        'magic': b'\x28\xb5\x2f\xfd',
        'parser': None,
    },
    {
        'name': 'GZIP compressed',
        'magic': b'\x1f\x8b',
        'parser': None,
    },
    {
        'name': 'BZIP2 compressed',
        'magic': b'BZh',
        'parser': None,
    },
    {
        'name': 'XZ compressed',
        'magic': b'\xfd\x37\x7a\x58\x5a\x00',
        'parser': None,
    },

    # Network / Config
    {
        'name': 'TLS Certificate',
        'magic': b'-----BEGIN CERTIFICATE',
        'parser': None,
    },
    {
        'name': 'RSA Private Key',
        'magic': b'-----BEGIN RSA PRIVATE',
        'parser': None,
    },
    {
        'name': 'OpenSSH Private Key',
        'magic': b'-----BEGIN OPENSSH PRIVATE',
        'parser': None,
    },
]


def _parse_uboot(data, offset):
    """Parse U-Boot uImage header."""
    info = {}
    try:
        fmt = '>IIIIIIIBBBB32s'
        fields = struct.unpack(fmt, data[offset:offset + 64])
        info['Header CRC'] = f"0x{fields[1]:08x}"
        info['Timestamp'] = fields[2]
        info['Data Size'] = format_size(fields[3])
        info['Load Address'] = f"0x{fields[4]:08x}"
        info['Entry Point'] = f"0x{fields[5]:08x}"

        os_types = {0: 'Invalid', 1: 'OpenBSD', 2: 'NetBSD', 3: 'FreeBSD',
                    4: 'BSD4.4', 5: 'Linux', 6: 'SVR4', 7: 'Esix',
                    8: 'Solaris', 9: 'Irix', 10: 'SCO', 11: 'Dell',
                    12: 'NCR', 13: 'LynxOS', 14: 'VxWorks', 15: 'pSOS',
                    16: 'QNX', 17: 'U-Boot'}
        info['OS'] = os_types.get(fields[7], f'Unknown ({fields[7]})')

        arch_types = {0: 'Invalid', 1: 'Alpha', 2: 'ARM', 3: 'x86',
                      4: 'IA64', 5: 'MIPS', 6: 'MIPS64', 7: 'PowerPC',
                      8: 'S390', 9: 'SuperH', 10: 'SPARC', 11: 'SPARC64',
                      12: 'M68K', 15: 'ARM64', 22: 'RISC-V'}
        info['Architecture'] = arch_types.get(fields[8], f'Unknown ({fields[8]})')

        img_types = {0: 'Invalid', 1: 'Standalone', 2: 'Kernel', 3: 'RAMDisk',
                     4: 'Multi', 5: 'Firmware', 6: 'Script', 7: 'Filesystem'}
        info['Image Type'] = img_types.get(fields[9], f'Unknown ({fields[9]})')

        comp_types = {0: 'none', 1: 'gzip', 2: 'bzip2', 3: 'lzma',
                      4: 'lzo', 5: 'lz4', 6: 'zstd'}
        info['Compression'] = comp_types.get(fields[10], f'Unknown ({fields[10]})')

        name = fields[11].rstrip(b'\x00').decode('ascii', errors='replace')
        info['Image Name'] = name
    except (struct.error, IndexError):
        pass
    return info


def _parse_squashfs(data, offset):
    """Parse SquashFS header (little endian)."""
    info = {}
    try:
        inode_count = struct.unpack('<I', data[offset+4:offset+8])[0]
        mod_time = struct.unpack('<I', data[offset+8:offset+12])[0]
        block_size = struct.unpack('<I', data[offset+12:offset+16])[0]
        frag_count = struct.unpack('<I', data[offset+16:offset+20])[0]
        comp_type = struct.unpack('<H', data[offset+20:offset+22])[0]
        block_log = struct.unpack('<H', data[offset+22:offset+24])[0]
        fs_size = struct.unpack('<Q', data[offset+40:offset+48])[0]

        comp_names = {1: 'gzip', 2: 'lzma', 3: 'lzo', 4: 'xz', 5: 'lz4', 6: 'zstd'}
        info['Inodes'] = inode_count
        info['Block Size'] = format_size(block_size)
        info['Compression'] = comp_names.get(comp_type, f'Unknown ({comp_type})')
        info['Fragments'] = frag_count
        info['FS Size'] = format_size(fs_size)
    except (struct.error, IndexError):
        pass
    return info


def _parse_squashfs_be(data, offset):
    """Parse SquashFS header (big endian)."""
    info = {}
    try:
        block_size = struct.unpack('>I', data[offset+12:offset+16])[0]
        info['Block Size'] = format_size(block_size)
        info['Endianness'] = 'Big Endian'
    except (struct.error, IndexError):
        pass
    return info


def _parse_cramfs(data, offset):
    """Parse CramFS header."""
    info = {}
    try:
        size = struct.unpack('<I', data[offset+4:offset+8])[0]
        flags = struct.unpack('<I', data[offset+8:offset+12])[0]
        name = data[offset+48:offset+64].rstrip(b'\x00').decode('ascii', errors='replace')
        info['Size'] = format_size(size)
        info['Name'] = name
    except (struct.error, IndexError):
        pass
    return info


def _parse_linux_version(data, offset):
    """Extract Linux kernel version string."""
    info = {}
    try:
        end = data.find(b'\x00', offset)
        if end != -1 and end - offset < 256:
            version = data[offset:end].decode('ascii', errors='replace')
            info['Version'] = version
    except Exception:
        pass
    return info


def _parse_dtb(data, offset):
    """Parse Device Tree Blob header."""
    info = {}
    try:
        total_size = struct.unpack('>I', data[offset+4:offset+8])[0]
        off_struct = struct.unpack('>I', data[offset+8:offset+12])[0]
        off_strings = struct.unpack('>I', data[offset+12:offset+16])[0]
        version = struct.unpack('>I', data[offset+20:offset+24])[0]
        info['Total Size'] = format_size(total_size)
        info['Version'] = version
    except (struct.error, IndexError):
        pass
    return info


def scan_firmware(data):
    """Scan firmware for known structures."""
    results = []
    parsers = {
        '_parse_uboot': _parse_uboot,
        '_parse_squashfs': _parse_squashfs,
        '_parse_squashfs_be': _parse_squashfs_be,
        '_parse_cramfs': _parse_cramfs,
        '_parse_linux_version': _parse_linux_version,
        '_parse_dtb': _parse_dtb,
    }

    for header in FIRMWARE_HEADERS:
        magic = header['magic']
        check_offset = header.get('offset', None)

        if check_offset is not None:
            # Only check at specific offset
            if check_offset + len(magic) <= len(data):
                if data[check_offset:check_offset + len(magic)] == magic:
                    result = {
                        'offset': check_offset,
                        'name': header['name'],
                        'details': {},
                    }
                    results.append(result)
            continue

        # Scan entire file
        offset = 0
        while offset < len(data):
            idx = data.find(magic, offset)
            if idx == -1:
                break

            result = {
                'offset': idx,
                'name': header['name'],
                'details': {},
            }

            # Parse details if parser available
            if header['parser'] and header['parser'] in parsers:
                result['details'] = parsers[header['parser']](data, idx)

            results.append(result)
            offset = idx + len(magic)

    results.sort(key=lambda x: x['offset'])
    return results


# ─── Interesting Strings ──────────────────────────────────────────────────────

def find_firmware_strings(data, flag_format=None):
    """Find interesting strings in firmware (URLs, IPs, passwords, etc.)."""
    findings = {
        'urls': [],
        'ips': [],
        'emails': [],
        'passwords': [],
        'keys': [],
        'flags': [],
        'interesting': [],
    }

    text = data.decode('latin-1', errors='replace')

    # URLs
    for m in re.finditer(r'https?://[^\s\x00<>"\']+', text):
        findings['urls'].append((m.start(), m.group()))

    # IPs
    for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text):
        ip = m.group(1)
        octets = ip.split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            if ip not in ('0.0.0.0', '255.255.255.255', '127.0.0.1'):
                findings['ips'].append((m.start(), ip))

    # Emails
    for m in re.finditer(r'[\w.+-]+@[\w-]+\.[\w.]+', text):
        findings['emails'].append((m.start(), m.group()))

    # Password-like entries
    for m in re.finditer(r'(?:password|passwd|pwd|secret|token|api.?key)\s*[:=]\s*["\']?([^\s"\'<>]+)',
                          text, re.IGNORECASE):
        findings['passwords'].append((m.start(), m.group()))

    # SSH/RSA keys
    for m in re.finditer(r'-----BEGIN\s+\w+\s+(PRIVATE\s+)?KEY-----', text):
        findings['keys'].append((m.start(), m.group()))

    # Flags
    patterns = [r'flag\{[^}]+\}', r'CTF\{[^}]+\}', r'FLAG\{[^}]+\}',
                r'picoCTF\{[^}]+\}', r'HTB\{[^}]+\}']
    if flag_format:
        patterns.append(flag_format)

    for pattern in patterns:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings['flags'].append((m.start(), m.group()))

    # Interesting paths
    for m in re.finditer(r'/(?:etc|var|tmp|root|home|usr|bin|sbin)/[\w./-]+', text):
        findings['interesting'].append((m.start(), m.group()))

    return findings


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF Firmware Analyzer — headers, filesystems, and secrets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s firmware.bin
  %(prog)s router.bin --all
  %(prog)s iot_dump.bin --strings
  %(prog)s blob.bin --flag-format 'myctf\\{.*?\\}'
        """
    )
    parser.add_argument('file', help='Firmware file to analyze')
    parser.add_argument('--strings', '-s', action='store_true',
                        help='Search for interesting strings (URLs, IPs, passwords)')
    parser.add_argument('--flag-format', '-f', type=str,
                        help='Custom flag regex pattern')
    parser.add_argument('--all', '-a', action='store_true',
                        help='Run all analyses')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output as JSON')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    if args.all:
        args.strings = True

    if not os.path.isfile(args.file):
        print(f"{C.RED}Error: '{args.file}' not found.{C.RESET}", file=sys.stderr)
        sys.exit(1)

    with open(args.file, 'rb') as f:
        data = f.read()

    file_size = len(data)

    if args.json:
        import json
        output = {'file': os.path.abspath(args.file), 'file_size': file_size}
        results = scan_firmware(data)
        output['structures'] = [{'offset': r['offset'], 'offset_hex': f"0x{r['offset']:08x}",
                                  'name': r['name'], 'details': r['details']} for r in results]
        if args.strings:
            findings = find_firmware_strings(data, args.flag_format)
            output['strings'] = {k: [(off, s) for off, s in v] for k, v in findings.items()}
        print(json.dumps(output, indent=2, default=str))
        return

    # ── Header ────────────────────────────────────────────────────────────
    print_header(f"Firmware Analysis: {os.path.basename(args.file)}")
    print_field('File Size', f'{file_size:,} bytes ({format_size(file_size)})')

    # Entropy overview
    from collections import Counter
    byte_freq = Counter(data)
    null_pct = byte_freq.get(0, 0) / file_size * 100
    ff_pct = byte_freq.get(0xFF, 0) / file_size * 100
    print_field('Null bytes (0x00)', f'{null_pct:.1f}%')
    print_field('Full bytes (0xFF)', f'{ff_pct:.1f}%')

    # Architecture hints
    if data[:4] == b'\x7fELF':
        arch = {1: '32-bit', 2: '64-bit'}.get(data[4], 'Unknown')
        endian = {1: 'Little Endian', 2: 'Big Endian'}.get(data[5], 'Unknown')
        print_field('Architecture', f'ELF {arch} {endian}')
    elif b'\x00\x00\xa0\xe1' in data[:16]:
        print_field('Architecture', 'ARM (detected)')
    elif data[:2] == b'MZ':
        print_field('Architecture', 'x86 PE')

    # ── Firmware Structures ───────────────────────────────────────────────
    results = scan_firmware(data)

    print_header(f"Detected Structures ({len(results)} found)")

    if not results:
        print(f"  {C.YELLOW}No known firmware structures detected.{C.RESET}")
    else:
        for r in results:
            print(f"\n  {C.BOLD}{C.MAGENTA}{r['name']}{C.RESET}")
            print(f"  {C.DIM}Offset: 0x{r['offset']:08x} ({r['offset']:,}){C.RESET}")
            for key, value in r['details'].items():
                print_field(f'  {key}', str(value))

    # ── Interesting Strings ───────────────────────────────────────────────
    if args.strings:
        findings = find_firmware_strings(data, args.flag_format)

        if findings['flags']:
            print_header("⚑ FLAGS FOUND!")
            for offset, flag in findings['flags']:
                print(f"  {C.RED}{C.BOLD}0x{offset:08x}  {flag}{C.RESET}")

        categories = [
            ('URLs', findings['urls'], C.BLUE),
            ('IP Addresses', findings['ips'], C.YELLOW),
            ('Emails', findings['emails'], C.GREEN),
            ('Passwords/Secrets', findings['passwords'], C.RED),
            ('Crypto Keys', findings['keys'], C.RED),
            ('Filesystem Paths', findings['interesting'], C.CYAN),
        ]

        has_findings = any(v for _, v, _ in categories)
        if has_findings:
            print_header("Interesting Strings")
            for category, items, color in categories:
                if items:
                    print(f"\n  {C.BOLD}{category} ({len(items)}):{C.RESET}")
                    for offset, value in items[:15]:
                        print(f"    {C.DIM}0x{offset:08x}{C.RESET}  {color}{value}{C.RESET}")
                    if len(items) > 15:
                        print(f"    {C.DIM}... and {len(items) - 15} more{C.RESET}")

    print()


if __name__ == '__main__':
    main()

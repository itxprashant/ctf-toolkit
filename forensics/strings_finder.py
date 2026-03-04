#!/usr/bin/env python3
"""
strings_finder.py - CTF String Extraction Tool

Extracts printable strings from any file with flag pattern highlighting.
Supports ASCII and UTF-16 string extraction with offset display.

Usage:
    python3 strings_finder.py <file>
    python3 strings_finder.py binary.dat --min-length 8
    python3 strings_finder.py challenge.bin --flag-format 'picoCTF\\{.*?\\}'
    python3 strings_finder.py firmware.bin --encoding utf-16 --output strings.txt
"""

import argparse
import os
import re
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


# Common flag patterns used across popular CTF competitions
DEFAULT_FLAG_PATTERNS = [
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'ctf\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'picoCTF\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'TUCTF\{[^}]+\}',
    r'uiuctf\{[^}]+\}',
]


def extract_ascii_strings(data, min_length=4):
    """Extract ASCII printable strings with their offsets."""
    strings = []
    current = []
    start_offset = 0

    for i, byte in enumerate(data):
        if 32 <= byte < 127:  # Printable ASCII
            if not current:
                start_offset = i
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append((start_offset, ''.join(current), 'ASCII'))
            current = []

    if len(current) >= min_length:
        strings.append((start_offset, ''.join(current), 'ASCII'))

    return strings


def extract_utf16_strings(data, min_length=4, endian='little'):
    """Extract UTF-16 encoded strings with their offsets."""
    strings = []
    current = []
    start_offset = 0
    step = 2

    for i in range(0, len(data) - 1, step):
        if endian == 'little':
            char_val = data[i] | (data[i + 1] << 8)
        else:
            char_val = (data[i] << 8) | data[i + 1]

        if 32 <= char_val < 127:  # Printable ASCII in UTF-16
            if not current:
                start_offset = i
            current.append(chr(char_val))
        else:
            if len(current) >= min_length:
                strings.append((start_offset, ''.join(current), f'UTF-16{endian[0].upper()}E'))
            current = []

    if len(current) >= min_length:
        strings.append((start_offset, ''.join(current), f'UTF-16{endian[0].upper()}E'))

    return strings


def check_flag_patterns(string, patterns):
    """Check if a string matches any flag patterns."""
    matches = []
    for pattern in patterns:
        found = re.findall(pattern, string, re.IGNORECASE)
        matches.extend(found)
    return matches


def categorize_string(s):
    """Categorize a string for CTF relevance."""
    categories = []

    # URLs
    if re.search(r'https?://', s):
        categories.append('URL')

    # Email
    if re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', s):
        categories.append('EMAIL')

    # File paths
    if re.search(r'[/\\][\w./-]+\.\w+', s):
        categories.append('PATH')

    # Base64 (long enough to be interesting)
    if re.match(r'^[A-Za-z0-9+/]{16,}={0,2}$', s):
        categories.append('BASE64?')

    # Hex string
    if re.match(r'^[0-9a-fA-F]{16,}$', s):
        categories.append('HEX?')

    # Password-like
    if re.search(r'(password|passwd|pwd|secret|key|token)', s, re.IGNORECASE):
        categories.append('CREDENTIAL?')

    return categories


def print_header(text):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 60}")
    print(f"  {text}")
    print(f"{'─' * 60}{C.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='CTF Strings Finder — extract strings with flag highlighting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s challenge.bin
  %(prog)s firmware.bin --min-length 8 --encoding both
  %(prog)s mystery.dat --flag-format 'picoCTF\\{.*?\\}'
  %(prog)s binary --interesting-only
  %(prog)s data.bin --output strings.txt
        """
    )
    parser.add_argument('file', help='File to extract strings from')
    parser.add_argument('--min-length', '-n', type=int, default=4,
                        help='Minimum string length (default: 4)')
    parser.add_argument('--encoding', '-e', choices=['ascii', 'utf-16le', 'utf-16be', 'both'],
                        default='ascii', help='String encoding to search (default: ascii)')
    parser.add_argument('--flag-format', '-f', type=str, action='append',
                        help='Custom flag regex pattern (can be used multiple times)')
    parser.add_argument('--interesting-only', '-i', action='store_true',
                        help='Only show strings with interesting categories (URLs, base64, etc.)')
    parser.add_argument('--output', '-o', type=str,
                        help='Write results to file')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    parser.add_argument('--no-offset', action='store_true',
                        help='Don\'t show hex offsets')
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

    # Build flag patterns
    flag_patterns = list(DEFAULT_FLAG_PATTERNS)
    if args.flag_format:
        flag_patterns.extend(args.flag_format)

    # Extract strings
    all_strings = []

    if args.encoding in ('ascii', 'both'):
        all_strings.extend(extract_ascii_strings(data, args.min_length))

    if args.encoding in ('utf-16le', 'both'):
        all_strings.extend(extract_utf16_strings(data, args.min_length, 'little'))

    if args.encoding == 'utf-16be':
        all_strings.extend(extract_utf16_strings(data, args.min_length, 'big'))

    # Sort by offset
    all_strings.sort(key=lambda x: x[0])

    # Prepare output
    output_lines = []
    flags_found = []
    interesting_strings = []

    print_header(f"Strings: {os.path.basename(args.file)}")
    print(f"  {C.DIM}File size: {len(data):,} bytes | "
          f"Min length: {args.min_length} | "
          f"Encoding: {args.encoding}{C.RESET}")
    print(f"  {C.DIM}Found {len(all_strings)} strings{C.RESET}\n")

    for offset, string, encoding in all_strings:
        # Check for flags
        flag_matches = check_flag_patterns(string, flag_patterns)
        if flag_matches:
            flags_found.extend(flag_matches)

        # Categorize
        categories = categorize_string(string)

        if args.interesting_only and not categories and not flag_matches:
            continue

        # Format output line
        offset_str = f"{C.DIM}0x{offset:08x}{C.RESET} " if not args.no_offset else ""
        enc_str = f" {C.DIM}[{encoding}]{C.RESET}" if args.encoding == 'both' else ""

        if flag_matches:
            line = f"  {offset_str}{C.RED}{C.BOLD}⚑ {string}{C.RESET}{enc_str}"
            for fm in flag_matches:
                line += f"\n  {' ' * 12}{C.RED}{C.BOLD}  FLAG: {fm}{C.RESET}"
        elif categories:
            cat_str = ', '.join(categories)
            line = f"  {offset_str}{C.YELLOW}{string}{C.RESET} {C.MAGENTA}[{cat_str}]{C.RESET}{enc_str}"
            interesting_strings.append((offset, string, categories))
        else:
            line = f"  {offset_str}{string}{enc_str}"

        print(line)
        output_lines.append(f"0x{offset:08x}\t{encoding}\t{string}")

    # Summary
    print_header("Summary")
    print(f"  {C.BOLD}Total strings:{C.RESET}       {len(all_strings)}")
    print(f"  {C.BOLD}Interesting strings:{C.RESET} {len(interesting_strings)}")

    if flags_found:
        print(f"\n  {C.RED}{C.BOLD}{'═' * 40}")
        print(f"  ⚑ FLAGS FOUND: {len(flags_found)}")
        print(f"  {'═' * 40}{C.RESET}")
        for flag in flags_found:
            print(f"  {C.RED}{C.BOLD}  → {flag}{C.RESET}")

    # Write to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            f.write('\n'.join(output_lines) + '\n')
        print(f"\n  {C.GREEN}Output saved to: {args.output}{C.RESET}")

    print()


if __name__ == '__main__':
    main()

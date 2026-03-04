#!/usr/bin/env python3
"""
hex_viewer.py - CTF Hex Dump Viewer

Classic hex dump with search, highlighting, and pattern matching.
Supports piping from stdin for integration with other tools.

Usage:
    python3 hex_viewer.py <file>
    python3 hex_viewer.py binary.dat --offset 0x100 --length 256
    python3 hex_viewer.py challenge.bin --search "flag{"
    python3 hex_viewer.py data.bin --search-hex "89504e47"
    cat file | python3 hex_viewer.py -
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
    BG_YELLOW = '\033[43m'
    BG_RED    = '\033[41m'


def hex_dump(data, start_offset=0, bytes_per_line=16, highlight_ranges=None):
    """Generate a hex dump with optional byte highlighting."""
    if highlight_ranges is None:
        highlight_ranges = []

    lines = []

    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        abs_offset = start_offset + i

        # Offset column
        line_hex = f"{C.DIM}0x{abs_offset:08x}{C.RESET}  "

        # Hex columns
        hex_parts = []
        ascii_parts = []

        for j, byte in enumerate(chunk):
            pos = start_offset + i + j
            is_highlighted = any(s <= pos < s + l for s, l in highlight_ranges)

            hex_str = f'{byte:02x}'
            if is_highlighted:
                hex_parts.append(f'{C.BG_YELLOW}{C.BOLD}{hex_str}{C.RESET}')
            elif byte == 0x00:
                hex_parts.append(f'{C.DIM}{hex_str}{C.RESET}')
            elif 32 <= byte < 127:
                hex_parts.append(f'{C.GREEN}{hex_str}{C.RESET}')
            else:
                hex_parts.append(hex_str)

            # ASCII column
            if is_highlighted:
                c = chr(byte) if 32 <= byte < 127 else '.'
                ascii_parts.append(f'{C.BG_YELLOW}{C.BOLD}{c}{C.RESET}')
            elif 32 <= byte < 127:
                ascii_parts.append(f'{C.GREEN}{chr(byte)}{C.RESET}')
            else:
                ascii_parts.append(f'{C.DIM}.{C.RESET}')

            # Add extra space in the middle for readability
            if j == 7:
                hex_parts.append(' ')

        # Pad if last line is short
        padding = bytes_per_line - len(chunk)
        for _ in range(padding):
            hex_parts.append('  ')
        if len(chunk) <= 8:
            hex_parts.append(' ')

        hex_str = ' '.join(hex_parts)
        ascii_str = ''.join(ascii_parts)

        line = f"  {line_hex}{hex_str}  {C.DIM}│{C.RESET}{ascii_str}{C.DIM}│{C.RESET}"
        lines.append(line)

    return '\n'.join(lines)


def search_bytes(data, pattern_bytes, context=32):
    """Search for a byte pattern and return matches with context."""
    matches = []
    offset = 0
    while True:
        idx = data.find(pattern_bytes, offset)
        if idx == -1:
            break
        # Get context around match
        ctx_start = max(0, idx - context)
        ctx_end = min(len(data), idx + len(pattern_bytes) + context)
        matches.append({
            'offset': idx,
            'context_start': ctx_start,
            'context_data': data[ctx_start:ctx_end],
            'match_length': len(pattern_bytes),
        })
        offset = idx + 1
    return matches


def print_header(text):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 70}")
    print(f"  {text}")
    print(f"{'─' * 70}{C.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='CTF Hex Viewer — hex dump with search and highlighting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s binary.dat
  %(prog)s binary.dat --offset 0x100 --length 512
  %(prog)s challenge.bin --search "flag{"
  %(prog)s challenge.bin --search-hex "504b0304"
  %(prog)s data.bin --highlight-hex "ffff"
  cat file | %(prog)s -
        """
    )
    parser.add_argument('file', help='File to view (use - for stdin)')
    parser.add_argument('--offset', '-o', type=str, default='0',
                        help='Start offset (supports hex: 0x100)')
    parser.add_argument('--length', '-l', type=int, default=None,
                        help='Number of bytes to display (default: 512, or all with --search)')
    parser.add_argument('--width', '-w', type=int, default=16,
                        help='Bytes per line (default: 16)')
    parser.add_argument('--search', '-s', type=str,
                        help='Search for ASCII string')
    parser.add_argument('--search-hex', '-S', type=str,
                        help='Search for hex pattern (e.g., "89504e47")')
    parser.add_argument('--highlight-hex', '-H', type=str, action='append',
                        help='Highlight hex pattern (can be used multiple times)')
    parser.add_argument('--context', '-c', type=int, default=48,
                        help='Context bytes around search matches (default: 48)')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    # Read data
    if args.file == '-':
        data = sys.stdin.buffer.read()
        filename = '<stdin>'
    else:
        if not os.path.isfile(args.file):
            print(f"{C.RED}Error: '{args.file}' not found.{C.RESET}", file=sys.stderr)
            sys.exit(1)
        with open(args.file, 'rb') as f:
            data = f.read()
        filename = os.path.basename(args.file)

    # Parse offset
    start_offset = int(args.offset, 0)  # Auto-detect hex (0x) or decimal

    # ── Search Mode ───────────────────────────────────────────────────────
    if args.search or args.search_hex:
        if args.search:
            pattern_bytes = args.search.encode()
            pattern_display = args.search
        else:
            try:
                pattern_bytes = bytes.fromhex(args.search_hex)
                pattern_display = args.search_hex
            except ValueError:
                print(f"{C.RED}Error: Invalid hex pattern.{C.RESET}", file=sys.stderr)
                sys.exit(1)

        matches = search_bytes(data, pattern_bytes, args.context)

        print_header(f"Search Results: '{pattern_display}' in {filename}")
        print(f"  {C.DIM}Pattern: {' '.join(f'{b:02x}' for b in pattern_bytes)} "
              f"({len(pattern_bytes)} bytes){C.RESET}")
        print(f"  {C.DIM}Matches: {len(matches)}{C.RESET}")

        if not matches:
            print(f"\n  {C.YELLOW}No matches found.{C.RESET}\n")
            return

        for i, match in enumerate(matches):
            print(f"\n  {C.BOLD}{C.MAGENTA}Match #{i + 1} at offset "
                  f"0x{match['offset']:08x} ({match['offset']}){C.RESET}\n")

            highlight = [(match['offset'], match['match_length'])]
            print(hex_dump(match['context_data'], match['context_start'],
                           args.width, highlight))

        print()
        return

    # ── Dump Mode ─────────────────────────────────────────────────────────
    default_length = 512
    length = args.length if args.length else default_length
    display_data = data[start_offset:start_offset + length]

    # Build highlight ranges
    highlight_ranges = []
    if args.highlight_hex:
        for hex_pattern in args.highlight_hex:
            try:
                pattern_bytes = bytes.fromhex(hex_pattern)
                offset = start_offset
                while True:
                    idx = data.find(pattern_bytes, offset)
                    if idx == -1 or idx >= start_offset + length:
                        break
                    highlight_ranges.append((idx, len(pattern_bytes)))
                    offset = idx + 1
            except ValueError:
                print(f"{C.YELLOW}Warning: Invalid hex pattern '{hex_pattern}'{C.RESET}",
                      file=sys.stderr)

    print_header(f"Hex Dump: {filename}")
    print(f"  {C.DIM}File size: {len(data):,} bytes | "
          f"Showing: 0x{start_offset:08x} - 0x{start_offset + len(display_data):08x} "
          f"({len(display_data)} bytes){C.RESET}\n")

    print(hex_dump(display_data, start_offset, args.width, highlight_ranges))
    print()

    if start_offset + length < len(data):
        remaining = len(data) - (start_offset + length)
        print(f"  {C.DIM}... {remaining:,} more bytes. "
              f"Use --offset 0x{start_offset + length:x} to continue.{C.RESET}\n")


if __name__ == '__main__':
    main()

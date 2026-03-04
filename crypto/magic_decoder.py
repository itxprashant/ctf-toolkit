#!/usr/bin/env python3
"""
magic_decoder.py - CTF Magic Decoder Toolkit

Recursively tries common CTF encodings:
Base64, Base32, Base58, Base85, Hex, Decimal, Octal, URL-encoding, ROT13
"""

import argparse
import base64
import re
import string
import sys
import urllib.parse
from typing import List, Tuple, Optional

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

# Base58 alphabet (Bitcoin)
B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def is_mostly_printable(data: bytes, threshold=0.90) -> bool:
    """Check if the byte string is mostly printable ASCII."""
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(data)) >= threshold


def check_flag(data: bytes) -> bool:
    """Check if the byte string contains a common CTO flag format."""
    try:
        text = data.decode('utf-8', errors='ignore').lower()
        if 'flag{' in text or 'ctf{' in text or 'picoctf{' in text or 'htb{' in text:
            return True
    except:
        pass
    return False


def decode_rot13(data: bytes) -> Optional[bytes]:
    """Apply ROT13 to alphabet characters."""
    try:
        text = data.decode('utf-8')
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr(((ord(char) - ord('a') + 13) % 26) + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr(((ord(char) - ord('A') + 13) % 26) + ord('A')))
            else:
                result.append(char)
        return "".join(result).encode('utf-8')
    except:
        return None


def decode_base58(data: bytes) -> Optional[bytes]:
    """Decode Base58 (Bitcoin alphabet)."""
    try:
        s = data.decode('ascii').strip()
        n = 0
        for char in s:
            n = n * 58 + B58_ALPHABET.index(char.encode('ascii'))
        
        # Convert integer to bytes
        h = hex(n)[2:]
        if len(h) % 2 != 0:
            h = '0' + h
        return bytes.fromhex(h)
    except:
        return None

# ─── Decoders Array ──────────────────────────────────────────────────────────

DECODERS = [
    ("Base64", lambda d: base64.b64decode(d, validate=True)),
    ("Base32", lambda d: base64.b32decode(d, casefold=True, validate=True)),
    ("Base85", lambda d: base64.b85decode(d)),
    ("Base58", decode_base58),
    ("Hex", lambda d: bytes.fromhex(d.decode('ascii').strip().replace(' ', '').replace('\\x', '').replace('%', ''))),
    ("URL", lambda d: urllib.parse.unquote_to_bytes(d.decode('ascii')) if '%' in d.decode('ascii') else ValueError()),
    ("ROT13", decode_rot13),
    ("Decimal Space-Separated", lambda d: bytes([int(x) for x in d.decode('ascii').split()])),
    ("Octal Space-Separated", lambda d: bytes([int(x, 8) for x in d.decode('ascii').split()])),
    ("Binary Space-Separated", lambda d: bytes([int(x, 2) for x in d.decode('ascii').split()])),
]


def recursive_decode(data: bytes, depth=0, max_depth=10, path: List[str] = None) -> List[Tuple[List[str], bytes]]:
    """
    Recursively tries all decoders.
    Returns: list of (path_of_decoders, final_decoded_bytes)
    """
    if path is None:
        path = []
        
    results = []
    
    # Base case: we found a flag!
    if check_flag(data):
        return [(path, data)]
        
    if depth >= max_depth:
        # If it's mostly printable, keep it as a partial result
        if is_mostly_printable(data) and path:
            return [(path, data)]
        return []

    # Try every decoder
    found_any = False
    for name, func in DECODERS:
        try:
            decoded = func(data)
            if decoded and decoded != data: # Prevent infinite ROT13 loops or no-ops
                found_any = True
                new_path = path + [name]
                sub_results = recursive_decode(decoded, depth + 1, max_depth, new_path)
                results.extend(sub_results)
        except Exception:
            continue
            
    # If no decoders worked, but current data is printable text, save it
    if not found_any and path and is_mostly_printable(data):
        results.append((path, data))

    return results


def main():
    parser = argparse.ArgumentParser(
        description='CTF Magic Decoder Toolkit\nRecursively tries common encodings.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('input', help='String to decode or @filename to read from file')
    parser.add_argument('-d', '--max-depth', type=int, default=10, help='Maximum recursion depth (default: 10)')
    
    args = parser.parse_args()
    
    # ── Load data ──
    try:
        if args.input.startswith('@'):
            filepath = args.input[1:]
            with open(filepath, 'rb') as f:
                data = f.read().strip()
        else:
            data = args.input.encode('utf-8')
    except Exception as e:
        print(f"{C.RED}Error loading data: {e}{C.RESET}")
        sys.exit(1)

    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  Magic Decoder Toolkit\n{'─' * 60}{C.RESET}")
    print(f"  Input size: {len(data)} bytes\n")

    print(f"  {C.YELLOW}⟳ Trying all decoding combinations (max depth {args.max_depth})...{C.RESET}\n")

    results = recursive_decode(data, max_depth=args.max_depth)

    if not results:
        print(f"  {C.RED}✗ Could not find any valid nested encodings that result in readable text.{C.RESET}\n")
        return

    # Deduplicate and sort results (prefer flags, then shortest paths)
    unique_results = {}
    for path, final_data in results:
        # Tuple of path to keep it hashable, store shortest path for same data
        if final_data not in unique_results or len(path) < len(unique_results[final_data]):
            unique_results[final_data] = path

    # Sort results
    def score_result(item):
        final_data, path = item
        is_flag = check_flag(final_data)
        return (not is_flag, len(path))
        
    sorted_results = sorted(unique_results.items(), key=score_result)

    found_flag = False
    for final_data, path in sorted_results:
        is_flag = check_flag(final_data)
        
        if is_flag:
            found_flag = True
            print(f"  {C.GREEN}{C.BOLD}★ FLAG FOUND! ★{C.RESET}")
        else:
            print(f"  {C.CYAN}▶ Valid Decoding Path Found:{C.RESET}")
            
        print(f"    {C.DIM}Path:{C.RESET} {' ➔ '.join(path)}")
        
        try:
            text = final_data.decode('utf-8')
            if len(text) > 200:
                print(f"    {C.DIM}Result (excerpt):{C.RESET} {text[:197]}...")
            else:
                if is_flag:
                    print(f"    {C.RED}{C.BOLD}Result:{C.RESET} {text}")
                else:
                    print(f"    {C.DIM}Result:{C.RESET} {text}")
        except UnicodeDecodeError:
            print(f"    {C.DIM}Result (hex):{C.RESET} {final_data.hex()[:100]}")
            
        print()
        
        # Stop after first flag
        if is_flag:
            break

    if not found_flag:
        print(f"  {C.YELLOW}Note: Checked all paths but no obvious flag format was detected.{C.RESET}")
        print(f"  {C.YELLOW}Review the valid decodings above.{C.RESET}\n")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
magic_decoder.py - CTF Magic Decoder Toolkit

Recursively tries common CTF encodings:
Base64, Base32, Base58, Base85, Hex, Decimal, Octal, Binary,
URL-encoding, ROT13, ROT47, Morse Code, A1Z26, Braille, Tap Code
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

# Morse code lookup
MORSE_TO_CHAR = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
    '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
    '-----': '0', '-.-.--': '!', '.-.-.-': '.', '--..--': ',', '..--..': '?',
    '-..-.': '/', '.--.-.': '@', '---...': ':', '-.--.-': ')', '-.--.': '(',
    '.----.': "'", '-....-': '-', '..--.-': '_', '-.-.-.': ';',
    '.-..-.': '"', '.-...': '&', '...-.-': '$',
    '.-.-': '{', '-.-.-': '}',
}

# Braille Unicode to ASCII
BRAILLE_MAP = {
    '⠁': 'a', '⠃': 'b', '⠉': 'c', '⠙': 'd', '⠑': 'e',
    '⠋': 'f', '⠛': 'g', '⠓': 'h', '⠊': 'i', '⠚': 'j',
    '⠅': 'k', '⠇': 'l', '⠍': 'm', '⠝': 'n', '⠕': 'o',
    '⠏': 'p', '⠟': 'q', '⠗': 'r', '⠎': 's', '⠞': 't',
    '⠥': 'u', '⠧': 'v', '⠺': 'w', '⠭': 'x', '⠽': 'y',
    '⠵': 'z', '⠀': ' ', '⠂': ',', '⠲': '.', '⠦': '?',
    '⠖': '!', '⠄': "'", '⠤': '-',
    '⠼⠁': '1', '⠼⠃': '2', '⠼⠉': '3', '⠼⠙': '4', '⠼⠑': '5',
    '⠼⠋': '6', '⠼⠛': '7', '⠼⠓': '8', '⠼⠊': '9', '⠼⠚': '0',
}

# Tap code (Polybius cipher variant, used by POWs)
TAP_GRID = [
    ['A', 'B', 'C', 'D', 'E'],
    ['F', 'G', 'H', 'I', 'J'],
    ['L', 'M', 'N', 'O', 'P'],
    ['Q', 'R', 'S', 'T', 'U'],
    ['V', 'W', 'X', 'Y', 'Z'],
]

FLAG_PATTERNS = [
    r'flag\{[^}]+\}', r'ctf\{[^}]+\}', r'FLAG\{[^}]+\}', r'CTF\{[^}]+\}',
    r'picoCTF\{[^}]+\}', r'HTB\{[^}]+\}', r'DUCTF\{[^}]+\}', r'TryHackMe\{[^}]+\}',
]


def is_mostly_printable(data: bytes, threshold=0.90) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(data)) >= threshold


def check_flag(data: bytes) -> bool:
    try:
        text = data.decode('utf-8', errors='ignore')
        for pattern in FLAG_PATTERNS:
            if re.search(pattern, text):
                return True
    except:
        pass
    return False


def extract_flags(data: bytes) -> list:
    """Extract all flag-format strings from data."""
    results = []
    try:
        text = data.decode('utf-8', errors='ignore')
        for pattern in FLAG_PATTERNS:
            results.extend(re.findall(pattern, text))
    except:
        pass
    return results


# ─── Decoders ─────────────────────────────────────────────────────────────────

def decode_rot13(data: bytes) -> Optional[bytes]:
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


def decode_rot47(data: bytes) -> Optional[bytes]:
    """ROT47 — rotates printable ASCII range (! to ~)."""
    try:
        text = data.decode('ascii')
        result = []
        for c in text:
            o = ord(c)
            if 33 <= o <= 126:
                result.append(chr(33 + ((o - 33 + 47) % 94)))
            else:
                result.append(c)
        return "".join(result).encode('utf-8')
    except:
        return None


def decode_base58(data: bytes) -> Optional[bytes]:
    try:
        s = data.decode('ascii').strip()
        n = 0
        for char in s:
            n = n * 58 + B58_ALPHABET.index(char.encode('ascii'))
        h = hex(n)[2:]
        if len(h) % 2 != 0:
            h = '0' + h
        return bytes.fromhex(h)
    except:
        return None


def decode_morse(data: bytes) -> Optional[bytes]:
    """Decode morse code. Accepts . - / and spaces."""
    try:
        text = data.decode('ascii').strip()
        # Normalize separators
        text = text.replace('|', '/').replace('  ', ' / ')
        words = text.split('/')
        result = []
        for word in words:
            word = word.strip()
            if not word:
                result.append(' ')
                continue
            letters = word.split()
            for letter in letters:
                letter = letter.strip()
                if letter in MORSE_TO_CHAR:
                    result.append(MORSE_TO_CHAR[letter])
                elif letter:
                    return None  # Invalid morse
            result.append(' ')
        decoded = ''.join(result).strip()
        if decoded:
            return decoded.encode('utf-8')
    except:
        pass
    return None


def decode_a1z26(data: bytes) -> Optional[bytes]:
    """A1Z26 cipher: numbers map to letters (1=A, 26=Z)."""
    try:
        text = data.decode('ascii').strip()
        # Split by common separators
        nums = re.split(r'[,\s\-_]+', text)
        result = []
        for num in nums:
            num = num.strip()
            if not num:
                continue
            n = int(num)
            if 1 <= n <= 26:
                result.append(chr(n + ord('a') - 1))
            else:
                return None
        if result:
            return ''.join(result).encode('utf-8')
    except:
        pass
    return None


def decode_braille(data: bytes) -> Optional[bytes]:
    """Decode Unicode Braille characters to ASCII."""
    try:
        text = data.decode('utf-8')
        if not any(0x2800 <= ord(c) <= 0x28FF for c in text):
            return None
        result = []
        for char in text:
            if char in BRAILLE_MAP:
                result.append(BRAILLE_MAP[char])
            elif 0x2800 <= ord(char) <= 0x28FF:
                result.append('?')
            else:
                result.append(char)
        decoded = ''.join(result)
        if decoded:
            return decoded.encode('utf-8')
    except:
        pass
    return None


def decode_tap_code(data: bytes) -> Optional[bytes]:
    """Tap code: pairs of numbers (row, col) in the 5×5 Polybius grid."""
    try:
        text = data.decode('ascii').strip()
        # Common format: "1,1 2,3 4,4" or "11 23 44" or "1-1 2-3 4-4"
        pairs = re.findall(r'(\d)[,\-\s]?(\d)', text)
        if not pairs or len(pairs) < 2:
            return None
        result = []
        for row, col in pairs:
            r, c = int(row) - 1, int(col) - 1
            if 0 <= r <= 4 and 0 <= c <= 4:
                result.append(TAP_GRID[r][c])
            else:
                return None
        if result:
            return ''.join(result).encode('utf-8')
    except:
        pass
    return None


def decode_binary_ascii(data: bytes) -> Optional[bytes]:
    """Decode space-separated binary strings to ASCII chars."""
    try:
        text = data.decode('ascii').strip()
        if not re.match(r'^[01\s]+$', text):
            return None
        chunks = text.split()
        if not all(len(c) in (7, 8) for c in chunks):
            return None
        result = bytes([int(c, 2) for c in chunks])
        if is_mostly_printable(result, 0.8):
            return result
    except:
        pass
    return None


def decode_decimal_csv(data: bytes) -> Optional[bytes]:
    """Decode comma or space separated decimal numbers to bytes."""
    try:
        text = data.decode('ascii').strip()
        nums = re.split(r'[,\s]+', text)
        ints = [int(n.strip()) for n in nums if n.strip()]
        if all(0 <= n <= 255 for n in ints) and len(ints) >= 3:
            result = bytes(ints)
            if is_mostly_printable(result, 0.7):
                return result
    except:
        pass
    return None


def decode_octal_csv(data: bytes) -> Optional[bytes]:
    """Decode space-separated octal numbers."""
    try:
        text = data.decode('ascii').strip()
        nums = re.split(r'[,\s]+', text)
        ints = [int(n.strip(), 8) for n in nums if n.strip()]
        if all(0 <= n <= 255 for n in ints) and len(ints) >= 3:
            return bytes(ints)
    except:
        pass
    return None


DECODERS = [
    ("Base64",         lambda d: base64.b64decode(d, validate=True)),
    ("Base32",         lambda d: base64.b32decode(d, casefold=True)),
    ("Base85",         lambda d: base64.b85decode(d)),
    ("Base58",         decode_base58),
    ("Hex",            lambda d: bytes.fromhex(d.decode('ascii').strip().replace(' ', '').replace('\\x', '').replace('0x', ''))),
    ("URL Decode",     lambda d: urllib.parse.unquote_to_bytes(d.decode('ascii')) if '%' in d.decode('ascii') else (_ for _ in ()).throw(ValueError())),
    ("ROT13",          decode_rot13),
    ("ROT47",          decode_rot47),
    ("Morse Code",     decode_morse),
    ("A1Z26",          decode_a1z26),
    ("Braille",        decode_braille),
    ("Tap Code",       decode_tap_code),
    ("Binary ASCII",   decode_binary_ascii),
    ("Decimal",        decode_decimal_csv),
    ("Octal",          decode_octal_csv),
]


def recursive_decode(data: bytes, depth=0, max_depth=10, path: List[str] = None) -> List[Tuple[List[str], bytes]]:
    if path is None:
        path = []

    results = []

    if check_flag(data):
        return [(path, data)]

    if depth >= max_depth:
        if is_mostly_printable(data) and path:
            return [(path, data)]
        return []

    found_any = False
    for name, func in DECODERS:
        try:
            decoded = func(data)
            if decoded and decoded != data and len(decoded) >= 2:
                found_any = True
                new_path = path + [name]
                sub_results = recursive_decode(decoded, depth + 1, max_depth, new_path)
                results.extend(sub_results)
        except Exception:
            continue

    if not found_any and path and is_mostly_printable(data):
        results.append((path, data))

    return results


def try_single_decoders(data: bytes):
    """Try each decoder once (non-recursive) and show all results."""
    results = []
    for name, func in DECODERS:
        try:
            decoded = func(data)
            if decoded and decoded != data and len(decoded) >= 2:
                results.append((name, decoded))
        except Exception:
            continue
    return results


def main():
    parser = argparse.ArgumentParser(
        description='CTF Magic Decoder — Recursive Encoding Breaker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Encodings supported:
  Base64, Base32, Base58, Base85, Hex, Decimal, Octal, Binary,
  URL, ROT13, ROT47, Morse Code, A1Z26, Braille, Tap Code

Examples:
  %(prog)s 'Wm14blEzTmpNak16'           # Recursive decode
  %(prog)s @encoded.txt                   # From file
  %(prog)s '.- -... -.-..' --single       # Morse code (single pass)
  %(prog)s '1,2 3,4 5,1' --single        # Tap code
""")

    parser.add_argument('input', help='String to decode or @filename to read from file')
    parser.add_argument('-d', '--max-depth', type=int, default=10, help='Maximum recursion depth (default: 10)')
    parser.add_argument('-s', '--single', action='store_true', help='Single pass only (no recursion, shows all decoders)')
    parser.add_argument('-o', '--output', help='Save decoded result to file')

    args = parser.parse_args()

    try:
        if args.input.startswith('@'):
            with open(args.input[1:], 'rb') as f:
                data = f.read().strip()
        else:
            data = args.input.encode('utf-8')
    except Exception as e:
        print(f"{C.RED}Error loading data: {e}{C.RESET}")
        sys.exit(1)

    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  Magic Decoder\n{'─' * 60}{C.RESET}")
    print(f"  Input size: {len(data)} bytes\n")

    # ── Single pass mode ──
    if args.single:
        print(f"  {C.YELLOW}Single-pass mode: trying all decoders once{C.RESET}\n")
        results = try_single_decoders(data)

        if not results:
            print(f"  {C.RED}✗ No decoder produced valid output.{C.RESET}\n")
            return

        for name, decoded in results:
            is_flag = check_flag(decoded)
            marker = f"{C.RED}{C.BOLD}⚑ FLAG" if is_flag else f"{C.CYAN}▶"
            try:
                text = decoded.decode('utf-8', errors='replace')
                if len(text) > 120:
                    text = text[:117] + '...'
                print(f"  {marker} {name:20s}{C.RESET} → {text}")
            except:
                print(f"  {marker} {name:20s}{C.RESET} → (binary: {decoded[:30].hex()})")

            if is_flag:
                flags = extract_flags(decoded)
                for f in flags:
                    print(f"      {C.RED}{C.BOLD}→ {f}{C.RESET}")
        print()
        return

    # ── Recursive mode ──
    print(f"  {C.YELLOW}⟳ Trying all decoding combinations (max depth {args.max_depth})...{C.RESET}\n")

    results = recursive_decode(data, max_depth=args.max_depth)

    if not results:
        print(f"  {C.RED}✗ No valid nested encodings found.{C.RESET}\n")
        return

    # Deduplicate
    unique_results = {}
    for path, final_data in results:
        if final_data not in unique_results or len(path) < len(unique_results[final_data]):
            unique_results[final_data] = path

    def score_result(item):
        final_data, path = item
        return (not check_flag(final_data), len(path))

    sorted_results = sorted(unique_results.items(), key=score_result)

    for final_data, path in sorted_results[:10]:
        is_flag = check_flag(final_data)

        if is_flag:
            print(f"  {C.GREEN}{C.BOLD}★ FLAG FOUND! ★{C.RESET}")
        else:
            print(f"  {C.CYAN}▶ Valid Decoding Path:{C.RESET}")

        print(f"    {C.DIM}Path:{C.RESET} {' → '.join(path)}")

        try:
            text = final_data.decode('utf-8')
            if len(text) > 200:
                print(f"    {C.DIM}Result (excerpt):{C.RESET} {text[:197]}...")
            elif is_flag:
                print(f"    {C.RED}{C.BOLD}Result:{C.RESET} {text}")
                flags = extract_flags(final_data)
                for f in flags:
                    print(f"    {C.RED}{C.BOLD}  → {f}{C.RESET}")
            else:
                print(f"    {C.DIM}Result:{C.RESET} {text}")
        except UnicodeDecodeError:
            print(f"    {C.DIM}Result (hex):{C.RESET} {final_data.hex()[:100]}")

        if args.output and is_flag:
            with open(args.output, 'wb') as f:
                f.write(final_data)
            print(f"    {C.GREEN}Saved to: {args.output}{C.RESET}")

        print()
        if is_flag:
            break

    if not any(check_flag(d) for d in unique_results):
        print(f"  {C.YELLOW}No flag format detected. Review decoded results above.{C.RESET}\n")


if __name__ == '__main__':
    main()

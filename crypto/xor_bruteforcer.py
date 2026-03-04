#!/usr/bin/env python3
"""
xor_bruteforcer.py - CTF XOR Decryption Toolkit

Automates XOR decryption:
- Single-byte XOR brute force using English frequency analysis
- Multi-byte repeating key XOR cracking (Hamming distance)
- Known plaintext / crib dragging attack
- File vs File XOR (two-time pad attack)
- Visual hex diff between original and decrypted
"""

import argparse
import sys
import string
import itertools
import os

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

# English letter frequencies (lowercase)
ENGLISH_FREQS = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00015,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
    'z': 0.00074, ' ': 0.13000
}

# Common English words for crib dragging
COMMON_CRIBS = [
    b'the ', b'The ', b'flag{', b'FLAG{', b'ctf{', b'CTF{', b'picoCTF{',
    b'HTB{', b'DUCTF{', b'http://', b'https://', b' the ', b'that ',
    b'this ', b'with ', b'have ', b'from ', b'they ', b'been ',
    b'password', b'admin', b'secret', b'key', b'flag',
    b'Hello', b'hello', b'Welcome', b'Dear ',
]


def xor_data(data: bytes, key: bytes) -> bytes:
    """XOR data with a repeating key."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def score_text(text: bytes) -> float:
    """Score English text using Chi-squared statistic."""
    freqs = {chr(i): 0 for i in range(97, 123)}
    freqs[' '] = 0
    total_chars = 0
    non_printable = 0

    for b in text:
        if b >= 128:
            non_printable += 1
            if non_printable > len(text) * 0.1:
                return float('inf')
            continue
        c = chr(b)
        if c.isprintable():
            c_low = c.lower()
            if c_low in freqs:
                freqs[c_low] += 1
            total_chars += 1
        else:
            if b not in (9, 10, 13):
                non_printable += 1
                if non_printable > len(text) * 0.1:
                    return float('inf')

    if total_chars == 0:
        return float('inf')

    chi_sq = 0.0
    for char, expected_pct in ENGLISH_FREQS.items():
        expected_count = total_chars * expected_pct
        actual_count = freqs[char]
        if expected_count > 0:
            chi_sq += ((actual_count - expected_count) ** 2) / expected_count

    return chi_sq


def single_byte_xor(ciphertext: bytes):
    """Try all 256 possible bytes and return the top results."""
    results = []
    for key_int in range(256):
        key = bytes([key_int])
        plaintext = xor_data(ciphertext, key)
        score = score_text(plaintext)
        if score != float('inf'):
            results.append((score, key, plaintext))

    results.sort(key=lambda x: x[0])
    return results


def hamming_distance(b1: bytes, b2: bytes) -> int:
    """Calculate bitwise Hamming distance between two byte strings."""
    dist = 0
    for byte1, byte2 in zip(b1, b2):
        dist += bin(byte1 ^ byte2).count('1')
    return dist


def guess_key_length(ciphertext: bytes, max_len: int = 40):
    """Estimate the most likely key lengths using normalized Hamming distance."""
    distances = []
    for keysize in range(2, min(max_len + 1, len(ciphertext) // 4)):
        blocks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)][:6]
        if len(blocks) < 2:
            break

        total_dist = 0
        pairs = 0
        for i in range(len(blocks)):
            for j in range(i + 1, len(blocks)):
                if len(blocks[i]) == keysize and len(blocks[j]) == keysize:
                    total_dist += hamming_distance(blocks[i], blocks[j])
                    pairs += 1

        if pairs > 0:
            avg_dist = total_dist / pairs
            norm_dist = avg_dist / keysize
            distances.append((norm_dist, keysize))

    distances.sort(key=lambda x: x[0])
    return [d[1] for d in distances[:5]]


def multi_byte_xor(ciphertext: bytes, keysize: int):
    """Break repeating-key XOR for a known keysize."""
    blocks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)]
    columns = [[] for _ in range(keysize)]
    for block in blocks:
        for i, b in enumerate(block):
            columns[i].append(b)

    key = bytearray()
    for col in columns:
        col_bytes = bytes(col)
        results = single_byte_xor(col_bytes)
        if results:
            key.append(results[0][1][0])
        else:
            key.append(0)

    if key and any(k != 0 for k in key):
        plaintext = xor_data(ciphertext, bytes(key))
        return bytes(key), plaintext
    return None, None


def crib_drag(ciphertext: bytes, crib: bytes):
    """Drag a known plaintext (crib) across the ciphertext to find positions."""
    results = []
    for pos in range(len(ciphertext) - len(crib) + 1):
        key_fragment = xor_data(ciphertext[pos:pos+len(crib)], crib)
        # Check if the key fragment looks reasonable (printable or repeating)
        printable_count = sum(1 for b in key_fragment if 32 <= b <= 126)
        if printable_count == len(key_fragment):
            results.append((pos, key_fragment, crib))
    return results


def two_time_pad(ct1: bytes, ct2: bytes):
    """XOR two ciphertexts together (two-time pad attack)."""
    xored = xor_data(ct1[:len(ct2)], ct2[:len(ct1)])
    return xored


def hex_diff(original: bytes, decrypted: bytes, width: int = 16):
    """Show a visual hex diff between original and decrypted."""
    lines = []
    length = min(len(original), len(decrypted), 256)  # Show first 256 bytes
    for offset in range(0, length, width):
        orig_chunk = original[offset:offset+width]
        dec_chunk = decrypted[offset:offset+width]

        hex_orig = ' '.join(f'{b:02x}' for b in orig_chunk)
        hex_dec = ' '.join(f'{b:02x}' for b in dec_chunk)
        ascii_dec = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in dec_chunk)

        lines.append(f"  {C.DIM}{offset:04x}:{C.RESET} {C.RED}{hex_orig:<{width*3}}{C.RESET} → {C.GREEN}{hex_dec:<{width*3}}{C.RESET} │{ascii_dec}│")
    return '\n'.join(lines)


def check_flag(data: bytes) -> bool:
    try:
        text = data.decode('utf-8', errors='ignore').lower()
        return 'flag{' in text or 'ctf{' in text or 'picoctf{' in text or 'htb{' in text
    except:
        return False


def main():
    parser = argparse.ArgumentParser(
        description='CTF XOR Decryption Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('file', help='Ciphertext file or hex string if using --hex')
    parser.add_argument('--hex', action='store_true', help='Interpret file argument as a hex string')
    parser.add_argument('--base64', action='store_true', help='Interpret file argument as a base64 string')
    parser.add_argument('--key', help='Decrypt with a known key (hex string)')

    subparsers = parser.add_subparsers(dest='mode', required=True)

    # Single-byte
    p_single = subparsers.add_parser('single', help='Single-byte XOR brute force')
    p_single.add_argument('-n', '--top', type=int, default=5, help='Number of top results to show')
    p_single.add_argument('--diff', action='store_true', help='Show hex diff for top result')

    # Multi-byte
    p_multi = subparsers.add_parser('repeating', help='Repeating-key XOR cracking')
    p_multi.add_argument('-k', '--keysize', type=int, help='Exact keysize (disables auto-guess)')
    p_multi.add_argument('-m', '--max-keysize', type=int, default=40, help='Max keysize to guess')
    p_multi.add_argument('--diff', action='store_true', help='Show hex diff')
    p_multi.add_argument('-o', '--output', help='Save decrypted output to file')

    # Crib dragging
    p_crib = subparsers.add_parser('crib', help='Known plaintext / crib dragging')
    p_crib.add_argument('--text', help='Custom crib text to drag')
    p_crib.add_argument('--auto', action='store_true', help='Try common English words and flag formats')

    # Two-time pad
    p_ttp = subparsers.add_parser('two-time-pad', help='XOR two ciphertexts (reused key)')
    p_ttp.add_argument('file2', help='Second ciphertext file')

    # Known key decrypt
    p_dec = subparsers.add_parser('decrypt', help='Decrypt with a known key')
    p_dec.add_argument('--key-hex', required=True, help='Key as hex string')
    p_dec.add_argument('-o', '--output', help='Save output to file')

    args = parser.parse_args()

    # ── Load data ──
    try:
        if args.hex:
            data = bytes.fromhex(args.file.replace(' ', ''))
        elif args.base64:
            import base64
            data = base64.b64decode(args.file)
        else:
            with open(args.file, 'rb') as f:
                data = f.read()
    except Exception as e:
        print(f"{C.RED}Error loading data: {e}{C.RESET}")
        sys.exit(1)

    if not data:
        print(f"{C.RED}Input data is empty.{C.RESET}")
        sys.exit(1)

    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  XOR Brute-Forcer\n{'─' * 60}{C.RESET}")
    print(f"  Input size: {len(data)} bytes")
    print(f"  Entropy: {_entropy(data):.4f} bits/byte\n")

    if args.mode == 'single':
        results = single_byte_xor(data)
        if not results:
            print(f"  {C.RED}No meaningful plaintext found.{C.RESET}\n")
            return

        print(f"  {C.BOLD}Top {args.top} results by English probability:{C.RESET}\n")
        for i, (score, key, ptext) in enumerate(results[:args.top]):
            p_str = ptext.decode('utf-8', errors='replace')
            if len(p_str) > 80:
                p_str = p_str[:77] + '...'

            key_char = chr(key[0]) if 32 <= key[0] <= 126 else '?'
            print(f"  [{i+1}] {C.GREEN}Key: 0x{key.hex()} ('{key_char}'){C.RESET}  {C.DIM}Score: {score:.2f}{C.RESET}")
            print(f"      {p_str}")

            if check_flag(ptext):
                print(f"      {C.RED}{C.BOLD}⚑ FLAG DETECTED!{C.RESET}")
            print()

        if hasattr(args, 'diff') and args.diff and results:
            print(f"  {C.BOLD}Hex Diff (Top Result):{C.RESET}")
            print(hex_diff(data, results[0][2]))
            print()

    elif args.mode == 'repeating':
        if len(data) < 10:
            print(f"  {C.YELLOW}Warning: Very short input ({len(data)} bytes).{C.RESET}\n")

        keysizes = [args.keysize] if args.keysize else guess_key_length(data, args.max_keysize)

        if not keysizes:
            print(f"  {C.RED}Failed to determine key length.{C.RESET}\n")
            return

        print(f"  Candidate key lengths: {keysizes}\n")

        found = False
        for ks in keysizes:
            print(f"  {C.CYAN}Keysize {ks}:{C.RESET}")
            key, ptext = multi_byte_xor(data, ks)
            if key:
                found = True
                key_printable = key.decode('utf-8', errors='replace')
                print(f"  {C.GREEN}▶ Key: {key} ('{key_printable}'){C.RESET}")
                print(f"  {C.GREEN}  Hex: {key.hex()}{C.RESET}")

                excerpt = ptext[:200].decode('utf-8', errors='replace')
                print(f"  {C.DIM}Excerpt:{C.RESET}\n  {excerpt}\n")

                if check_flag(ptext):
                    print(f"  {C.RED}{C.BOLD}⚑ FLAG DETECTED!{C.RESET}")
                    # Print the full decoded text to find the flag
                    full = ptext.decode('utf-8', errors='ignore')
                    import re
                    flags = re.findall(r'(?:flag|ctf|picoctf|htb)\{[^}]+\}', full, re.IGNORECASE)
                    for f in flags:
                        print(f"  {C.RED}{C.BOLD}  → {f}{C.RESET}")

                if hasattr(args, 'diff') and args.diff:
                    print(f"\n  {C.BOLD}Hex Diff:{C.RESET}")
                    print(hex_diff(data, ptext))

                if hasattr(args, 'output') and args.output:
                    with open(args.output, 'wb') as f:
                        f.write(ptext)
                    print(f"\n  {C.GREEN}Saved decrypted output to: {args.output}{C.RESET}")

                break  # Stop on first good result
            else:
                print(f"  {C.RED}✗ Failed for keysize {ks}{C.RESET}")

        if not found:
            print(f"\n  {C.RED}Could not crack repeating-key XOR.{C.RESET}")
        print()

    elif args.mode == 'crib':
        print(f"  {C.BOLD}Crib Dragging Attack{C.RESET}\n")
        cribs = []
        if hasattr(args, 'text') and args.text:
            cribs = [args.text.encode('utf-8')]
        elif hasattr(args, 'auto') and args.auto:
            cribs = COMMON_CRIBS
        else:
            cribs = COMMON_CRIBS  # Default to auto

        total_hits = 0
        for crib in cribs:
            results = crib_drag(data, crib)
            if results:
                for pos, key_frag, matched_crib in results:
                    total_hits += 1
                    key_str = key_frag.decode('utf-8', errors='replace')
                    print(f"  {C.GREEN}▶ Offset {pos:5d}{C.RESET} | Crib: {matched_crib.decode()} → Key fragment: '{C.YELLOW}{key_str}{C.RESET}' (0x{key_frag.hex()})")

        if total_hits == 0:
            print(f"  {C.RED}No crib matches found.{C.RESET}")
        else:
            print(f"\n  {C.DIM}Found {total_hits} potential key fragments.{C.RESET}")
        print()

    elif args.mode == 'two-time-pad':
        try:
            with open(args.file2, 'rb') as f:
                data2 = f.read()
        except Exception as e:
            print(f"{C.RED}Error loading second file: {e}{C.RESET}")
            sys.exit(1)

        xored = two_time_pad(data, data2)
        print(f"  {C.BOLD}Two-Time Pad: c1 ⊕ c2 = m1 ⊕ m2{C.RESET}")
        print(f"  XOR'd length: {len(xored)} bytes\n")

        # Check if XOR result has readable text
        printable = sum(1 for b in xored if 32 <= b <= 126)
        ratio = printable / len(xored) if xored else 0
        print(f"  Printable ratio: {ratio:.1%}")

        if ratio > 0.5:
            text = xored.decode('utf-8', errors='replace')
            print(f"  {C.GREEN}Looks like text!{C.RESET}")
            print(f"  {text[:200]}")
        else:
            print(f"  {C.DIM}Not directly readable. Try crib dragging on this output.{C.RESET}")
            print(f"  {C.DIM}Hex:{C.RESET} {xored[:64].hex()}")

        # Save XOR'd output
        out_path = 'xored_output.bin'
        with open(out_path, 'wb') as f:
            f.write(xored)
        print(f"\n  {C.GREEN}Saved XOR'd output to: {out_path}{C.RESET}\n")

    elif args.mode == 'decrypt':
        key = bytes.fromhex(args.key_hex.replace(' ', ''))
        ptext = xor_data(data, key)
        print(f"  {C.BOLD}Decrypting with key: {key} ({key.hex()}){C.RESET}\n")

        text = ptext.decode('utf-8', errors='replace')
        print(text[:500])

        if check_flag(ptext):
            print(f"\n  {C.RED}{C.BOLD}⚑ FLAG DETECTED!{C.RESET}")

        if hasattr(args, 'output') and args.output:
            with open(args.output, 'wb') as f:
                f.write(ptext)
            print(f"\n  {C.GREEN}Saved to: {args.output}{C.RESET}")
        print()


def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    from collections import Counter
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * (p.__class__(2).__rpow__(p) if False else p * __import__('math').log2(p))
    # Simpler:
    import math
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


if __name__ == '__main__':
    main()

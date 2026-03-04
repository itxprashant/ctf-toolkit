#!/usr/bin/env python3
"""
xor_bruteforcer.py - CTF XOR Decryption Toolkit

Automates XOR decryption:
- Single-byte XOR brute force using English frequency analysis
- Multi-byte repeating key XOR cracking (Hamming distance)
"""

import argparse
import sys
import string
import itertools

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

# English letter frequencies (lowercase)
ENGLISH_FREQS = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00015,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
    'z': 0.00074, ' ': 0.13000
}

def xor_data(data: bytes, key: bytes) -> bytes:
    """XOR data with a repeating key."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def score_text(text: bytes) -> float:
    """
    Score English text using Chi-squared statistic against expected frequencies.
    Lower score is better (closer to English).
    Returns infinity if text contains lots of non-printable chars.
    """
    freqs = {chr(i): 0 for i in range(97, 123)}
    freqs[' '] = 0
    total_chars = 0
    non_printable = 0

    for b in text:
        if b >= 128:
            non_printable += 1
            if non_printable > len(text) * 0.1:  # More than 10% non-printable is junk
                return float('inf')
            continue
        c = chr(b)
        if c.isprintable():
            c_low = c.lower()
            if c_low in freqs:
                freqs[c_low] += 1
            total_chars += 1
        else:
            if b not in (9, 10, 13):  # tab, newline, cr
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
    """Try all 256 possible bytes and return the top results based on English scoring."""
    results = []
    for key_int in range(256):
        key = bytes([key_int])
        plaintext = xor_data(ciphertext, key)
        score = score_text(plaintext)
        if score != float('inf'):
            results.append((score, key, plaintext))
    
    # Sort by chi-squared score (lower = better)
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
    for keysize in range(2, min(max_len + 1, len(ciphertext) // 2)):
        # Take blocks and average the distances
        blocks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)][:4]
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
    return [d[1] for d in distances[:3]]


def multi_byte_xor(ciphertext: bytes, keysize: int):
    """Break repeating-key XOR for a known keysize."""
    # Transpose blocks
    blocks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)]
    columns = [[] for _ in range(keysize)]
    for block in blocks:
        for i, b in enumerate(block):
            columns[i].append(b)
            
    # Solve each column as single-byte XOR
    key = bytearray()
    for col in columns:
        col_bytes = bytes(col)
        results = single_byte_xor(col_bytes)
        if results:
            key.append(results[0][1][0])
        else:
            # Fallback if scoring fails
            key.append(0)
            
    if key and all(k != 0 for k in key):
        plaintext = xor_data(ciphertext, bytes(key))
        return bytes(key), plaintext
    return None, None


def main():
    parser = argparse.ArgumentParser(
        description='CTF XOR Decryption Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('file', help='Ciphertext file or hex string if using --hex')
    parser.add_argument('--hex', action='store_true', help='Interpret file argument as a hex string')
    parser.add_argument('--base64', action='store_true', help='Interpret file argument as a base64 string')
    
    subparsers = parser.add_subparsers(dest='mode', required=True)
    
    # Single-byte
    p_single = subparsers.add_parser('single', help='Single-byte XOR brute force')
    p_single.add_argument('-n', '--top', type=int, default=5, help='Number of top results to show')
    
    # Multi-byte
    p_multi = subparsers.add_parser('repeating', help='Repeating-key XOR cracking')
    p_multi.add_argument('-k', '--keysize', type=int, help='Exact keysize to use (disables auto-guess)')
    p_multi.add_argument('-m', '--max-keysize', type=int, default=40, help='Max keysize to guess')

    args = parser.parse_args()
    
    # ── Load data ──
    try:
        if args.hex:
            data = bytes.fromhex(args.file)
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
    print(f"  Input size: {len(data)} bytes\n")

    if args.mode == 'single':
        results = single_byte_xor(data)
        if not results:
            print(f"  {C.RED}No meaningful plaintext found (is this definitely single-byte XOR?){C.RESET}\n")
            return
            
        print(f"  {C.BOLD}Top results by English probability:{C.RESET}")
        for i, (score, key, ptext) in enumerate(results[:args.top]):
            # Try to decode to string safely
            p_str = repr(ptext)[2:-1]  # remove b'...'
            if len(p_str) > 60:
                p_str = p_str[:57] + '...'
                
            print(f"  [{i+1}] {C.GREEN}Key: 0x{key.hex()} ('{chr(key[0]) if 32 <= key[0] <= 126 else '?'}'){C.RESET}")
            print(f"      {C.DIM}Score: {score:.2f}{C.RESET}")
            print(f"      {p_str}")
            
            # Highlight CTF flags
            if b'flag{' in ptext.lower() or b'ctf{' in ptext.lower():
                print(f"      {C.RED}{C.BOLD}⚑ FLAG PATTERN DETECTED HERE!{C.RESET}")
        print()

    elif args.mode == 'repeating':
        if len(data) < 10:
            print(f"  {C.YELLOW}Warning: Input is very short ({len(data)} bytes). Statistics might fail.{C.RESET}\n")

        keysizes = [args.keysize] if args.keysize else guess_key_length(data, args.max_keysize)
        
        if not keysizes:
            print(f"  {C.RED}Failed to determine key length.{C.RESET}\n")
            return
            
        print(f"  Guessing key length(s): {keysizes}")
        
        found = False
        for ks in keysizes:
            print(f"\n  {C.CYAN}Testing Keysize: {ks}{C.RESET}")
            key, ptext = multi_byte_xor(data, ks)
            if key:
                found = True
                print(f"  {C.GREEN}▶ Recovered Key: {key}{C.RESET}")
                
                # Show excerpt
                excerpt = repr(ptext[:120])[2:-1]
                print(f"  {C.DIM}Excerpt:{C.RESET}\n  {excerpt}")
                
                if b'flag{' in ptext.lower() or b'ctf{' in ptext.lower():
                    print(f"\n  {C.RED}{C.BOLD}⚑ FLAG PATTERN DETECTED!{C.RESET}")
                    print(f"  {ptext.decode('utf-8', errors='ignore')}")
            else:
                print(f"  {C.RED}✗ Failed to recover key for size {ks}{C.RESET}")
                
        if not found:
            print(f"\n  {C.RED}Could not decrypt using repeating-key XOR.{C.RESET}")
        print()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
cipher_solver.py - Classical Cipher Solver Toolkit

Automates cracking of historical ciphers:
- Caesar Cipher (brute forces all 25 shifts)
- Vigenère Cipher (determines key length via Index of Coincidence)
- Atbash (simple substitution)
"""

import argparse
import sys
import string
import re
from collections import Counter

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

# English letter frequencies
ENGLISH_FREQS = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00015,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074
}

def clean_text(text):
    """Keep only alphabetic uppercase characters."""
    return re.sub(r'[^A-Z]', '', text.upper())

def check_flag(text):
    """Highlight if text looks like a flag."""
    if 'FLAG' in text or 'CTF' in text:
        return True
    return False

def score_text(text):
    """Score text based on English letter frequency (Chi-squared)."""
    cleaned = clean_text(text)
    if not cleaned: return float('inf')
    
    counts = Counter(cleaned)
    length = len(cleaned)
    
    chi_sq = 0.0
    for char, expected_pct in ENGLISH_FREQS.items():
        expected = length * expected_pct
        actual = counts.get(char, 0)
        if expected > 0:
            chi_sq += ((actual - expected) ** 2) / expected
            
    return chi_sq


# ─── Caesar Cipher ───────────────────────────────────────────────────────────

def decrypt_caesar(text, shift):
    """Decrypt text using a specific Caesar shift."""
    result = []
    for char in text:
        if char.isupper():
            result.append(chr(((ord(char) - ord('A') - shift) % 26) + ord('A')))
        elif char.islower():
            result.append(chr(((ord(char) - ord('a') - shift) % 26) + ord('a')))
        else:
            result.append(char)
    return "".join(result)


def solve_caesar(text):
    """Try all 25 shifts and score them."""
    results = []
    for shift in range(1, 26):
        plaintext = decrypt_caesar(text, shift)
        score = score_text(plaintext)
        results.append((score, shift, plaintext))
        
    results.sort(key=lambda x: x[0])
    return results[:5]


# ─── Atbash Cipher ───────────────────────────────────────────────────────────

def solve_atbash(text):
    """Decrypt using Atbash (A->Z, B->Y, etc)."""
    result = []
    for char in text:
        if char.isupper():
            result.append(chr(ord('Z') - (ord(char) - ord('A'))))
        elif char.islower():
            result.append(chr(ord('z') - (ord(char) - ord('a'))))
        else:
            result.append(char)
    return "".join(result)


# ─── Vigenère Cipher ─────────────────────────────────────────────────────────

def calculate_ioc(text):
    """Calculate Index of Coincidence for a string."""
    cleaned = clean_text(text)
    if len(cleaned) < 2: return 0.0
    
    counts = Counter(cleaned)
    ioc = 0.0
    n = len(cleaned)
    for count in counts.values():
        ioc += count * (count - 1)
    return ioc / (n * (n - 1))


def find_vigenere_key_length(text, max_len=20):
    """Find most probable key lengths using Index of Coincidence."""
    cleaned = clean_text(text)
    if not cleaned: return []
    
    iocs = []
    for length in range(2, min(max_len + 1, len(cleaned) // 2)):
        avg_ioc = 0.0
        for i in range(length):
            substring = cleaned[i::length]
            avg_ioc += calculate_ioc(substring)
        avg_ioc /= length
        iocs.append((avg_ioc, length))
        
    # English IoC is ~0.0667, random is ~0.0385
    # Sort by closeness to English IoC (reverse order to get highest IoC)
    iocs.sort(key=lambda x: x[0], reverse=True)
    return [l for ioc, l in iocs[:3]]


def solve_vigenere_with_length(text, key_len):
    """Break Vigenère cipher given a specific key length."""
    cleaned = clean_text(text)
    if not cleaned: return None, None
    
    key = []
    # Solve each column as a Caesar shift
    for i in range(key_len):
        substring = cleaned[i::key_len]
        
        # Test all 26 shifts for this column
        best_shift = 0
        best_score = float('inf')
        for shift in range(26):
            shifted_sub = decrypt_caesar(substring, shift)
            score = score_text(shifted_sub)
            if score < best_score:
                best_score = score
                best_shift = shift
                
        key.append(chr(best_shift + ord('A')))
        
    key_str = "".join(key)
    
    # Decrypt the original text (preserving punctuation)
    result = []
    key_idx = 0
    for char in text:
        if char.isalpha():
            shift = ord(key_str[key_idx % key_len]) - ord('A')
            if char.isupper():
                result.append(chr(((ord(char) - ord('A') - shift) % 26) + ord('A')))
            else:
                result.append(chr(((ord(char) - ord('a') - shift) % 26) + ord('a')))
            key_idx += 1
        else:
            result.append(char)
            
    return key_str, "".join(result)


def solve_vigenere(text):
    """Automatically find key length and solve Vigenère."""
    lengths = find_vigenere_key_length(text)
    results = []
    for length in lengths:
        key, plaintext = solve_vigenere_with_length(text, length)
        if key:
            score = score_text(plaintext)
            results.append((score, length, key, plaintext))
            
    results.sort(key=lambda x: x[0])
    return results


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF Classical Cipher Solver Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('input', help='Text to decrypt or @filename')
    
    subparsers = parser.add_subparsers(dest='cipher', required=True)
    
    subparsers.add_parser('caesar', help='Solve Caesar shift automatically')
    subparsers.add_parser('atbash', help='Solve Atbash cipher')
    
    p_vig = subparsers.add_parser('vigenere', help='Solve Vigenère cipher automatically')
    p_vig.add_argument('-k', '--key', help='Use a specific key (skips auto-solve)')
    
    p_all = subparsers.add_parser('all', help='Try all classical ciphers')

    args = parser.parse_args()
    
    # Load input
    try:
        if args.input.startswith('@'):
            with open(args.input[1:], 'r', encoding='utf-8') as f:
                text = f.read().strip()
        else:
            text = args.input
    except Exception as e:
        print(f"{C.RED}Error loading input: {e}{C.RESET}")
        sys.exit(1)

    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  Classical Cipher Solver\n{'─' * 60}{C.RESET}")
    print(f"  Input size: {len(text)} characters\n")

    def run_caesar():
        print(f"  {C.YELLOW}⟳ Testing Caesar Cipher...{C.RESET}")
        results = solve_caesar(text)
        print(f"  {C.BOLD}Top 3 Caesar Shifts:{C.RESET}")
        for i, (score, shift, ptext) in enumerate(results[:3]):
            excerpt = ptext[:150] + "..." if len(ptext) > 150 else ptext
            highlight = C.RED if check_flag(ptext.upper()) else C.GREEN
            print(f"  [{i+1}] {C.CYAN}Shift: {shift:2d}{C.RESET} | {highlight}{excerpt}{C.RESET}")
            if check_flag(ptext.upper()):
                print(f"      {C.RED}{C.BOLD}⚑ FLAG DETECTED!{C.RESET}")
        print()

    def run_atbash():
        print(f"  {C.YELLOW}⟳ Testing Atbash Cipher...{C.RESET}")
        ptext = solve_atbash(text)
        excerpt = ptext[:150] + "..." if len(ptext) > 150 else ptext
        highlight = C.RED if check_flag(ptext.upper()) else C.GREEN
        print(f"  {highlight}Result:{C.RESET} {excerpt}")
        if check_flag(ptext.upper()):
            print(f"  {C.RED}{C.BOLD}⚑ FLAG DETECTED!{C.RESET}")
        print()

    def run_vigenere():
        print(f"  {C.YELLOW}⟳ Testing Vigenère Cipher...{C.RESET}")
        if hasattr(args, 'key') and args.key:
            # Use specific key
            key_len = len(args.key)
            result = []
            key_idx = 0
            key_str = args.key.upper()
            for char in text:
                if char.isalpha():
                    shift = ord(key_str[key_idx % key_len]) - ord('A')
                    if char.isupper():
                        result.append(chr(((ord(char) - ord('A') - shift) % 26) + ord('A')))
                    else:
                        result.append(chr(((ord(char) - ord('a') - shift) % 26) + ord('a')))
                    key_idx += 1
                else:
                    result.append(char)
            ptext = "".join(result)
            excerpt = ptext[:150] + "..." if len(ptext) > 150 else ptext
            print(f"  {C.GREEN}Decrypted with key '{args.key}':{C.RESET} {excerpt}")
        else:
            # Auto-solve
            results = solve_vigenere(text)
            if not results:
                print(f"  {C.RED}✗ Failed to find a valid Vigenère key.{C.RESET}")
                return
                
            print(f"  {C.BOLD}Top Vigenère Guesses:{C.RESET}")
            for i, (score, length, key, ptext) in enumerate(results):
                excerpt = ptext[:150] + "..." if len(ptext) > 150 else ptext
                highlight = C.RED if check_flag(ptext.upper()) else C.GREEN
                print(f"  [{i+1}] {C.CYAN}Key: {key:<10} (len: {length}){C.RESET} | {highlight}{excerpt}{C.RESET}")
                if check_flag(ptext.upper()):
                    print(f"      {C.RED}{C.BOLD}⚑ FLAG DETECTED!{C.RESET}")
        print()

    if args.cipher == 'caesar':
        run_caesar()
    elif args.cipher == 'atbash':
        run_atbash()
    elif args.cipher == 'vigenere':
        run_vigenere()
    elif args.cipher == 'all':
        run_caesar()
        run_atbash()
        run_vigenere()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
hash_cracker.py - CTF Hash Cracking Tool

Brute force and wordlist attacks against common hash types.
Auto-detects hash type and supports multi-threaded cracking.

Usage:
    python3 hash_cracker.py <hash> --wordlist rockyou.txt
    python3 hash_cracker.py <hash> --brute --charset lower --max-length 6
    python3 hash_cracker.py --hash-file hashes.txt --wordlist passwords.txt
    python3 hash_cracker.py <hash> --wordlist words.txt --rules
"""

import argparse
import hashlib
import itertools
import os
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

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


# ─── Hash Type Detection ─────────────────────────────────────────────────────

HASH_TYPES = {
    32:  [('md5', hashlib.md5)],
    40:  [('sha1', hashlib.sha1)],
    56:  [('sha224', hashlib.sha224)],
    64:  [('sha256', hashlib.sha256)],
    96:  [('sha384', hashlib.sha384)],
    128: [('sha512', hashlib.sha512)],
}

# Additional hash formats
SPECIAL_HASHES = {
    '$1$':  'MD5 (Unix crypt)',
    '$2a$': 'bcrypt',
    '$2b$': 'bcrypt',
    '$5$':  'SHA-256 (Unix crypt)',
    '$6$':  'SHA-512 (Unix crypt)',
    '$apr1$': 'Apache MD5',
}

CHARSETS = {
    'lower':    string.ascii_lowercase,
    'upper':    string.ascii_uppercase,
    'alpha':    string.ascii_letters,
    'digits':   string.digits,
    'alnum':    string.ascii_letters + string.digits,
    'all':      string.ascii_letters + string.digits + string.punctuation,
    'hex':      string.hexdigits[:16],
    'custom':   '',
}


def detect_hash_type(hash_str):
    """Detect the hash type from its format."""
    # Check special prefixes
    for prefix, name in SPECIAL_HASHES.items():
        if hash_str.startswith(prefix):
            return name, None

    # Check by length
    clean = hash_str.strip().lower()
    if all(c in string.hexdigits for c in clean):
        types = HASH_TYPES.get(len(clean), [])
        if types:
            return types[0][0], types[0][1]

    return 'unknown', None


def hash_password(password, hash_func):
    """Hash a password with the given function."""
    if isinstance(password, str):
        password = password.encode()
    return hash_func(password).hexdigest()


def print_header(text):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 60}")
    print(f"  {text}")
    print(f"{'─' * 60}{C.RESET}")


def print_field(label, value, color=C.GREEN):
    print(f"  {C.BOLD}{label + ':':20s}{C.RESET} {color}{value}{C.RESET}")


# ─── Wordlist Mutations / Rules ──────────────────────────────────────────────

def apply_rules(word):
    """Generate common mutations of a word (leet speak, case, suffixes)."""
    mutations = [word]

    # Case variations
    mutations.append(word.lower())
    mutations.append(word.upper())
    mutations.append(word.capitalize())
    mutations.append(word.swapcase())

    # Common suffixes
    for suffix in ['1', '123', '!', '!!', '@', '#', '1!', '2024', '2025', '2026']:
        mutations.append(word + suffix)
        mutations.append(word.capitalize() + suffix)

    # Common prefixes
    for prefix in ['!', '@', '#', '123']:
        mutations.append(prefix + word)

    # Leet speak
    leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7', 'l': '1'}
    leet = word.lower()
    for orig, repl in leet_map.items():
        leet = leet.replace(orig, repl)
    if leet != word.lower():
        mutations.append(leet)
        mutations.append(leet.capitalize() if leet else leet)

    # Reversed
    mutations.append(word[::-1])

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for m in mutations:
        if m not in seen:
            seen.add(m)
            unique.append(m)

    return unique


# ─── Cracking Engines ────────────────────────────────────────────────────────

class CrackStatus:
    """Thread-safe cracking status tracker."""
    def __init__(self):
        self.found = False
        self.result = None
        self.attempts = 0
        self.lock = threading.Lock()

    def mark_found(self, password):
        with self.lock:
            self.found = True
            self.result = password

    def increment(self, count=1):
        with self.lock:
            self.attempts += count


def wordlist_attack(target_hash, hash_func, wordlist_path, use_rules=False, status=None):
    """Attack a hash using a wordlist file."""
    target = target_hash.lower().strip()

    try:
        with open(wordlist_path, 'r', errors='replace') as f:
            for line in f:
                if status and status.found:
                    return None

                word = line.strip()
                if not word:
                    continue

                candidates = apply_rules(word) if use_rules else [word]

                for candidate in candidates:
                    if status:
                        status.increment()
                    if hash_password(candidate, hash_func) == target:
                        if status:
                            status.mark_found(candidate)
                        return candidate

    except FileNotFoundError:
        print(f"{C.RED}Error: Wordlist '{wordlist_path}' not found.{C.RESET}", file=sys.stderr)
        return None

    return None


def brute_force_attack(target_hash, hash_func, charset, min_len, max_len, status=None):
    """Brute force a hash with all character combinations."""
    target = target_hash.lower().strip()

    for length in range(min_len, max_len + 1):
        if status and status.found:
            return None

        for combo in itertools.product(charset, repeat=length):
            if status and status.found:
                return None

            candidate = ''.join(combo)
            if status:
                status.increment()

            if hash_password(candidate, hash_func) == target:
                if status:
                    status.mark_found(candidate)
                return candidate

    return None


def crack_hash(target_hash, hash_func, hash_type, args):
    """Main cracking logic — tries wordlist and/or brute force."""
    status = CrackStatus()
    start_time = time.time()

    print_header(f"Cracking: {target_hash[:40]}...")
    print_field('Hash Type', hash_type.upper())

    # Progress reporter
    stop_progress = threading.Event()
    def progress_reporter():
        while not stop_progress.is_set():
            elapsed = time.time() - start_time
            rate = status.attempts / elapsed if elapsed > 0 else 0
            print(f"\r  {C.DIM}Attempts: {status.attempts:,} | "
                  f"Rate: {rate:,.0f}/s | "
                  f"Elapsed: {elapsed:.1f}s{C.RESET}", end='', flush=True)
            stop_progress.wait(0.5)

    progress_thread = threading.Thread(target=progress_reporter, daemon=True)
    progress_thread.start()

    result = None

    # Wordlist attack
    if args.wordlist:
        for wl in args.wordlist:
            result = wordlist_attack(target_hash, hash_func, wl, args.rules, status)
            if result:
                break

    # Brute force attack
    if not result and args.brute:
        charset = CHARSETS.get(args.charset, args.charset)
        if args.charset == 'custom' and args.custom_charset:
            charset = args.custom_charset
        result = brute_force_attack(target_hash, hash_func, charset,
                                     args.min_length, args.max_length, status)

    stop_progress.set()
    progress_thread.join()
    elapsed = time.time() - start_time
    print()  # Clear progress line

    if result:
        print(f"\n  {C.RED}{C.BOLD}{'═' * 40}")
        print(f"  ⚑ PASSWORD FOUND!")
        print(f"  {'═' * 40}{C.RESET}")
        print(f"  {C.GREEN}{C.BOLD}  Hash:     {target_hash}{C.RESET}")
        print(f"  {C.GREEN}{C.BOLD}  Password: {result}{C.RESET}")
        print(f"  {C.DIM}  Attempts: {status.attempts:,} in {elapsed:.2f}s{C.RESET}")
    else:
        print(f"\n  {C.YELLOW}✗ Password not found.{C.RESET}")
        print(f"  {C.DIM}  Attempts: {status.attempts:,} in {elapsed:.2f}s{C.RESET}")

    print()
    return result


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF Hash Cracker — wordlist and brute force attacks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
  %(prog)s 5f4dcc3b5aa765d61d8327deb882cf99 --brute --charset lower --max-length 6
  %(prog)s --hash-file hashes.txt --wordlist passwords.txt --rules
  %(prog)s e99a18c428cb38d5f260853678922e03 --wordlist words.txt --type md5

Known hash types (auto-detected by length):
  MD5 (32 chars) | SHA1 (40) | SHA256 (64) | SHA512 (128)
        """
    )
    parser.add_argument('hash', nargs='?', help='Hash to crack')
    parser.add_argument('--hash-file', '-H', type=str,
                        help='File containing hashes (one per line)')
    parser.add_argument('--type', '-t', type=str,
                        choices=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
                        help='Force hash type (default: auto-detect)')
    parser.add_argument('--wordlist', '-w', type=str, action='append',
                        help='Wordlist file(s) to use (can specify multiple)')
    parser.add_argument('--rules', '-r', action='store_true',
                        help='Apply mutation rules to wordlist entries')
    parser.add_argument('--brute', '-b', action='store_true',
                        help='Use brute force attack')
    parser.add_argument('--charset', '-c', type=str, default='alnum',
                        choices=list(CHARSETS.keys()),
                        help='Character set for brute force (default: alnum)')
    parser.add_argument('--custom-charset', type=str,
                        help='Custom character set string')
    parser.add_argument('--min-length', type=int, default=1,
                        help='Min password length for brute force (default: 1)')
    parser.add_argument('--max-length', '-m', type=int, default=6,
                        help='Max password length for brute force (default: 6)')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    if not args.hash and not args.hash_file:
        parser.error('Provide a hash or --hash-file')

    if not args.wordlist and not args.brute:
        parser.error('Specify --wordlist and/or --brute')

    # Collect hashes
    hashes = []
    if args.hash:
        hashes.append(args.hash)
    if args.hash_file:
        try:
            with open(args.hash_file) as f:
                for line in f:
                    h = line.strip()
                    if h and not h.startswith('#'):
                        hashes.append(h)
        except FileNotFoundError:
            print(f"{C.RED}Error: Hash file not found.{C.RESET}", file=sys.stderr)
            sys.exit(1)

    # Crack each hash
    results = {}
    for target in hashes:
        if args.type:
            hash_type = args.type
            hash_func = getattr(hashlib, args.type)
        else:
            hash_type, hash_func = detect_hash_type(target)

        if hash_func is None:
            print(f"{C.RED}Cannot crack hash type: {hash_type}{C.RESET}")
            print(f"{C.DIM}Use --type to specify manually{C.RESET}")
            continue

        result = crack_hash(target, hash_func, hash_type, args)
        if result:
            results[target] = result

    # Summary
    if len(hashes) > 1:
        print_header("Summary")
        print(f"  Cracked: {C.GREEN}{len(results)}{C.RESET} / {len(hashes)}")
        for h, p in results.items():
            print(f"  {C.DIM}{h[:32]}...{C.RESET} → {C.GREEN}{p}{C.RESET}")
        print()


if __name__ == '__main__':
    main()

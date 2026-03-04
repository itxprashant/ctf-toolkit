#!/usr/bin/env python3
"""
rsa_toolkit.py - CTF RSA Attack Toolkit

Automates common RSA attacks used in CTF challenges:
- Wiener's Attack (large d, e is large)
- Fermat's Factorization (p and q are very close)
- Small e (Hastad's Broadcast / Cube Root)
- Common Modulus Attack
- Pollard's p-1 Factorization
- FactorDB Online Lookup
- Known Factors from File
- Multi-Prime RSA (when n = p*q*r...)
- Hastad's Broadcast Attack (same m, different n)
- PKCS#1 v1.5 padding strip
- PEM/DER key file parsing
"""

import argparse
import itertools
import json
import math
import re
import sys
import urllib.request
import urllib.error
from typing import Optional, Tuple

try:
    from Crypto.Util.number import inverse, long_to_bytes, GCD
    from Crypto.PublicKey import RSA as CryptoRSA
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import gmpy2
    USE_GMPY2 = True
except ImportError:
    USE_GMPY2 = False

if not HAS_CRYPTO:
    def inverse(u, v):
        u3, v3 = int(u), int(v)
        u1, v1 = 1, 0
        while v3 > 0:
            q = u3 // v3
            u1, v1 = v1, u1 - v1 * q
            u3, v3 = v3, u3 - v3 * q
        while u1 < 0:
            u1 = u1 + v
        return u1

    def long_to_bytes(val, endianness='big'):
        length = max(1, (val.bit_length() + 7) // 8)
        return val.to_bytes(length, byteorder=endianness)

    def GCD(a, b):
        return math.gcd(a, b)


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


def print_header(title):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 60}\n  {title}\n{'─' * 60}{C.RESET}")

def print_field(label, value, color=C.GREEN):
    print(f"  {C.BOLD}{label + ':':28s}{C.RESET} {color}{value}{C.RESET}")

def print_success(msg, detail=None):
    print(f"  {C.GREEN}▶ {msg}{C.RESET}")
    if detail:
        print(f"    {C.YELLOW}{detail}{C.RESET}")

def print_fail(msg):
    print(f"  {C.RED}✗ {msg}{C.RESET}")

def print_info(msg):
    print(f"  {C.CYAN}⟳ {msg}{C.RESET}")

def check_flag(msg):
    val = msg.decode('utf-8', errors='ignore')
    if 'flag{' in val.lower() or 'ctf{' in val.lower() or (val.isprintable() and len(val) > 4):
        return f"Possible Flag: {val}"
    return None

def strip_pkcs15(data):
    """Strip PKCS#1 v1.5 padding from decrypted data."""
    if len(data) < 11:
        return data
    if data[0:2] == b'\x00\x02':
        idx = data.index(b'\x00', 2)
        return data[idx + 1:]
    return data


# ─── Attack: FactorDB Lookup ─────────────────────────────────────────────────

def factordb_lookup(n):
    """Try to factor n using factordb.com API."""
    try:
        url = f"http://factordb.com/api?query={n}"
        req = urllib.request.urlopen(url, timeout=10)
        data = json.loads(req.read().decode())
        
        status = data.get('status', '')
        factors = data.get('factors', [])
        
        if status in ('FF', 'CF'):  # Fully Factored or Composite Factored
            primes = []
            for factor, exp in factors:
                primes.extend([int(factor)] * int(exp))
            if len(primes) >= 2:
                return primes
        return None
    except Exception:
        return None


# ─── Attack: Pollard's p-1 ───────────────────────────────────────────────────

def pollards_p_minus_1(n, B1=100000):
    """Pollard's p-1 factorization. Works when p-1 has only small factors."""
    a = 2
    for j in range(2, B1 + 1):
        a = pow(a, j, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            return d, n // d
    return None, None


# ─── Attack: Pollard's Rho ───────────────────────────────────────────────────

def pollards_rho(n, max_iter=1000000):
    """Pollard's Rho algorithm for integer factorization."""
    if n % 2 == 0:
        return 2, n // 2
    
    import random
    x = random.randint(2, n - 1)
    y = x
    c = random.randint(1, n - 1)
    d = 1
    
    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = math.gcd(abs(x - y), n)
        max_iter -= 1
        if max_iter <= 0:
            return None, None
    
    if d != n:
        return d, n // d
    return None, None


# ─── Attack: Wiener's Attack ─────────────────────────────────────────────────

def rational_to_contfrac(x, y):
    a = x // y
    pquotients = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        pquotients.append(a)
    return pquotients

def convergents_from_contfrac(frac):
    convergents = []
    for i in range(len(frac)):
        convergents.append(contfrac_to_rational(frac[0:i]))
    return convergents

def contfrac_to_rational(frac):
    if len(frac) == 0: return (0, 1)
    elif len(frac) == 1: return (frac[0], 1)
    n = frac[-1]
    d = 1
    for i in range(2, len(frac)):
        n, d = frac[-i] * n + d, n
    n, d = frac[0] * n + d, n
    return (n, d)

def isqrt(n):
    if USE_GMPY2:
        return int(gmpy2.isqrt(n))
    if n < 0: return -1
    if n == 0: return 0
    x, y = n, (n + 1) // 2
    while y < x:
        x, y = y, (y + n // y) // 2
    return x

def wieners_attack(n, e):
    frac = rational_to_contfrac(e, n)
    convergents = convergents_from_contfrac(frac)

    for (k, d) in convergents:
        if k == 0: continue
        if (e * d - 1) % k != 0: continue

        phi = (e * d - 1) // k
        s = n - phi + 1
        discriminant = s*s - 4*n
        if discriminant >= 0:
            root = isqrt(discriminant)
            if root * root == discriminant and (s + root) % 2 == 0:
                return d
    return None


# ─── Attack: Fermat's Factorization ──────────────────────────────────────────

def fermats_factorization(n, max_iter=1000000):
    a = isqrt(n)
    if a * a == n:
        return a, a

    a += 1
    b2 = a*a - n
    b = isqrt(b2)
    count = 0

    while b * b != b2:
        a += 1
        b2 = a*a - n
        b = isqrt(b2)
        count += 1
        if count > max_iter:
            return None, None

    p = a - b
    q = a + b
    return p, q


# ─── Attack: Small e (Cube Root Attack) ──────────────────────────────────────

def integer_nth_root(y, n):
    if USE_GMPY2:
        return int(gmpy2.iroot(y, n)[0])

    low = 0
    high = 1
    while high ** n <= y:
        high *= 2
    while low < high:
        mid = (low + high) // 2
        if mid ** n <= y:
            low = mid + 1
        else:
            high = mid
    return low - 1

def small_e_attack(c, e, n=None):
    m = integer_nth_root(c, e)
    if m**e == c:
        return m
    return None


# ─── Attack: Hastad's Broadcast ──────────────────────────────────────────────

def hastads_broadcast(ciphertexts, moduli, e):
    """Hastad's broadcast: same message m encrypted with e different moduli."""
    if len(ciphertexts) < e or len(moduli) < e:
        return None

    # Chinese Remainder Theorem
    N = 1
    for n in moduli[:e]:
        N *= n

    M = 0
    for i in range(e):
        ni = moduli[i]
        Ni = N // ni
        yi = inverse(Ni, ni)
        M = (M + ciphertexts[i] * Ni * yi) % N

    m = integer_nth_root(M, e)
    if m ** e == M:
        return m
    return None


# ─── Attack: Common Modulus ──────────────────────────────────────────────────

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def common_modulus_attack(c1, c2, e1, e2, n):
    g, a, b = extended_gcd(e1, e2)
    if g != 1:
        return None

    if a < 0:
        c1 = inverse(c1, n)
        a = -a
    if b < 0:
        c2 = inverse(c2, n)
        b = -b

    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m


# ─── Multi-Prime RSA ─────────────────────────────────────────────────────────

def multi_prime_decrypt(c, e, factors):
    """Decrypt given a list of prime factors of n."""
    n = 1
    for p in factors:
        n *= p

    # Compute phi for multi-prime RSA
    phi = 1
    for p in factors:
        phi *= (p - 1)

    try:
        d = inverse(e, phi)
        m = pow(c, d, n)
        return m
    except Exception:
        return None


# ─── PEM Key Parser ──────────────────────────────────────────────────────────

def parse_key_file(filepath):
    """Parse a PEM/DER RSA key file and extract n, e, d."""
    if not HAS_CRYPTO:
        print(f"  {C.RED}PyCryptodome required for key parsing. pip install pycryptodome{C.RESET}")
        return None

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        key = CryptoRSA.import_key(data)
        result = {'n': key.n, 'e': key.e}
        if key.has_private():
            result['d'] = key.d
            result['p'] = key.p
            result['q'] = key.q
        return result
    except Exception as e:
        print(f"  {C.RED}Failed to parse key: {e}{C.RESET}")
        return None


# ─── Decrypt Helper ──────────────────────────────────────────────────────────

def try_decrypt_and_show(c, d, n, attack_name):
    """Given d, decrypt and display."""
    m = pow(c, d, n)
    msg_raw = long_to_bytes(m)
    msg_stripped = strip_pkcs15(msg_raw)

    print_success(f"{attack_name} Succeeded!")
    print_field("Private Key (d)", f"...{str(d)[-40:]}" if len(str(d)) > 50 else str(d))

    if msg_stripped != msg_raw:
        print_field("Decrypted (PKCS stripped)", msg_stripped, C.MAGENTA)
    else:
        print_field("Decrypted Bytes", msg_raw, C.MAGENTA)

    flag = check_flag(msg_stripped)
    if flag: print_success(flag)
    return True


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF RSA Attack Toolkit — Auto-breaks weak RSA',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Subcommands:
  single      Try all attacks on a single (n, e, c) set
  common-mod  Common Modulus attack (same n, different e)
  broadcast   Hastad's Broadcast attack (same m, different n, small e)
  parse-key   Extract n, e, d from PEM/DER key files
  factor      Just factor n (no decrypt)
""")

    subparsers = parser.add_subparsers(dest='command', help='Attack type')

    # ── Single ──
    parser_std = subparsers.add_parser('single', help='Try all attacks on a single n, e, c')
    parser_std.add_argument('-n', '--modulus', type=lambda x: int(x, 0), required=True, help='Modulus n')
    parser_std.add_argument('-e', '--exponent', type=lambda x: int(x, 0), required=True, help='Public exponent e')
    parser_std.add_argument('-c', '--ciphertext', type=lambda x: int(x, 0), required=True, help='Ciphertext c')
    parser_std.add_argument('--factors-file', help='File with known factors (one per line)')
    parser_std.add_argument('--no-factordb', action='store_true', help='Skip FactorDB online lookup')

    # ── Common Modulus ──
    parser_cm = subparsers.add_parser('common-mod', help='Common Modulus Attack')
    parser_cm.add_argument('-n', type=lambda x: int(x, 0), required=True, help='Common Modulus n')
    parser_cm.add_argument('--e1', type=lambda x: int(x, 0), required=True, help='Exponent 1')
    parser_cm.add_argument('--c1', type=lambda x: int(x, 0), required=True, help='Ciphertext 1')
    parser_cm.add_argument('--e2', type=lambda x: int(x, 0), required=True, help='Exponent 2')
    parser_cm.add_argument('--c2', type=lambda x: int(x, 0), required=True, help='Ciphertext 2')

    # ── Broadcast ──
    parser_bc = subparsers.add_parser('broadcast', help="Hastad's Broadcast Attack")
    parser_bc.add_argument('-e', type=int, default=3, help='Public exponent (default: 3)')
    parser_bc.add_argument('--data', required=True, help='JSON file with [{n, c}, ...] pairs')

    # ── Parse Key ──
    parser_pk = subparsers.add_parser('parse-key', help='Parse PEM/DER key file')
    parser_pk.add_argument('keyfile', help='Path to PEM or DER key file')
    parser_pk.add_argument('-c', '--ciphertext', type=lambda x: int(x, 0), help='Ciphertext to decrypt with extracted key')

    # ── Factor ──
    parser_fc = subparsers.add_parser('factor', help='Factor n without decrypting')
    parser_fc.add_argument('-n', type=lambda x: int(x, 0), required=True, help='Number to factor')

    args = parser.parse_args()

    if not USE_GMPY2:
        print(f"{C.YELLOW}Note: gmpy2 not installed. Using slower native math.{C.RESET}\n")

    if args.command == 'single':
        n, e, c = args.modulus, args.exponent, args.ciphertext
        print_header("RSA Single-Target Attacks")
        print_field("Modulus (n)", f"{str(n)[:60]}{'...' if len(str(n)) > 60 else ''} ({n.bit_length()} bits)")
        print_field("Exponent (e)", e)
        print()

        # 0. Known Factors from file
        if args.factors_file:
            print_info("Loading factors from file...")
            try:
                with open(args.factors_file) as f:
                    factors = [int(line.strip()) for line in f if line.strip().isdigit()]
                if factors:
                    print_success(f"Loaded {len(factors)} factors from file")
                    m = multi_prime_decrypt(c, e, factors)
                    if m:
                        msg = strip_pkcs15(long_to_bytes(m))
                        print_field("Decrypted", msg, C.MAGENTA)
                        flag = check_flag(msg)
                        if flag: print_success(flag)
                        return
            except Exception as ex:
                print_fail(f"Error loading factors: {ex}")

        # 1. Small e
        if e <= 17:
            print_info(f"Testing Small e Attack (e={e})...")
            m = small_e_attack(c, e)
            if m:
                msg = strip_pkcs15(long_to_bytes(m))
                print_success("Small e Attack Succeeded!")
                print_field("Decrypted", msg, C.MAGENTA)
                flag = check_flag(msg)
                if flag: print_success(flag)
                return
            print_fail("Small e Attack failed.")
            print()

        # 2. Wiener's Attack
        print_info("Testing Wiener's Attack (large d)...")
        d = wieners_attack(n, e)
        if d:
            if try_decrypt_and_show(c, d, n, "Wiener's Attack"):
                return
        print_fail("Wiener's Attack failed.")
        print()

        # 3. FactorDB
        if not args.no_factordb:
            print_info("Checking FactorDB (online)...")
            factors = factordb_lookup(n)
            if factors:
                print_success(f"FactorDB returned {len(factors)} factors!")
                for i, f_val in enumerate(factors):
                    print_field(f"  Factor {i+1}", f_val)
                m = multi_prime_decrypt(c, e, factors)
                if m:
                    msg = strip_pkcs15(long_to_bytes(m))
                    print_field("Decrypted", msg, C.MAGENTA)
                    flag = check_flag(msg)
                    if flag: print_success(flag)
                    return
            else:
                print_fail("FactorDB: not factored or unreachable.")
            print()

        # 4. Fermat's
        print_info("Testing Fermat's Factorization (close p & q)...")
        p, q = fermats_factorization(n)
        if p and q:
            print_success("Fermat's Factorization Succeeded!")
            print_field("p", p)
            print_field("q", q)
            try:
                phi = (p - 1) * (q - 1)
                d = inverse(e, phi)
                if try_decrypt_and_show(c, d, n, "Fermat's"):
                    return
            except Exception as ex:
                print_fail(f"Could not derive d: {ex}")
        else:
            print_fail("Fermat's failed (primes not close enough).")
        print()

        # 5. Pollard's p-1
        print_info("Testing Pollard's p-1 (smooth prime factors)...")
        p, q = pollards_p_minus_1(n)
        if p and q:
            print_success("Pollard's p-1 Succeeded!")
            print_field("p", p)
            print_field("q", q)
            try:
                phi = (p - 1) * (q - 1)
                d = inverse(e, phi)
                if try_decrypt_and_show(c, d, n, "Pollard's p-1"):
                    return
            except Exception as ex:
                print_fail(f"Could not derive d: {ex}")
        else:
            print_fail("Pollard's p-1 failed.")
        print()

        # 6. Pollard's Rho (small n)
        if n.bit_length() <= 256:
            print_info("Testing Pollard's Rho (small modulus)...")
            p, q = pollards_rho(n)
            if p and q:
                print_success("Pollard's Rho Succeeded!")
                print_field("p", p)
                print_field("q", q)
                phi = (p - 1) * (q - 1)
                d = inverse(e, phi)
                if try_decrypt_and_show(c, d, n, "Pollard's Rho"):
                    return
            else:
                print_fail("Pollard's Rho failed.")
            print()

        print(f"\n{C.RED}All attacks exhausted.{C.RESET}\n")

    elif args.command == 'common-mod':
        print_header("Common Modulus Attack")
        m = common_modulus_attack(args.c1, args.c2, args.e1, args.e2, args.n)
        if m is not None:
            msg = strip_pkcs15(long_to_bytes(m))
            print_success("Common Modulus Attack Succeeded!")
            print_field("Decrypted", msg, C.MAGENTA)
            flag = check_flag(msg)
            if flag: print_success(flag)
        else:
            print_fail("Common Modulus Attack failed (exponents not coprime).")

    elif args.command == 'broadcast':
        print_header("Hastad's Broadcast Attack")
        try:
            with open(args.data) as f:
                pairs = json.load(f)
            moduli = [p['n'] for p in pairs]
            ciphertexts = [p['c'] for p in pairs]
        except Exception as ex:
            print_fail(f"Error loading JSON data: {ex}")
            sys.exit(1)

        print_field("Exponent (e)", args.e)
        print_field("Pairs loaded", len(pairs))

        m = hastads_broadcast(ciphertexts, moduli, args.e)
        if m:
            msg = strip_pkcs15(long_to_bytes(m))
            print_success("Broadcast Attack Succeeded!")
            print_field("Decrypted", msg, C.MAGENTA)
            flag = check_flag(msg)
            if flag: print_success(flag)
        else:
            print_fail("Broadcast Attack failed.")

    elif args.command == 'parse-key':
        print_header("RSA Key File Parser")
        result = parse_key_file(args.keyfile)
        if result:
            print_field("n", f"{str(result['n'])[:60]}... ({result['n'].bit_length()} bits)")
            print_field("e", result['e'])
            if 'd' in result:
                print_field("d", f"{str(result['d'])[:60]}...")
                print_field("p", result.get('p', 'N/A'))
                print_field("q", result.get('q', 'N/A'))
                print_success("Private key found!")

                if args.ciphertext:
                    m = pow(args.ciphertext, result['d'], result['n'])
                    msg = strip_pkcs15(long_to_bytes(m))
                    print_field("Decrypted", msg, C.MAGENTA)
                    flag = check_flag(msg)
                    if flag: print_success(flag)
            else:
                print_field("Type", "Public key only (no d)")

    elif args.command == 'factor':
        print_header("Factorization")
        n = args.n
        print_field("n", f"{str(n)[:60]}... ({n.bit_length()} bits)")

        print_info("Checking FactorDB...")
        factors = factordb_lookup(n)
        if factors:
            print_success(f"Factors found: {factors}")
            return

        print_info("Trying Pollard's p-1...")
        p, q = pollards_p_minus_1(n)
        if p: print_success(f"Factors: {p} × {q}"); return

        print_info("Trying Fermat's...")
        p, q = fermats_factorization(n)
        if p: print_success(f"Factors: {p} × {q}"); return

        if n.bit_length() <= 256:
            print_info("Trying Pollard's Rho...")
            p, q = pollards_rho(n)
            if p: print_success(f"Factors: {p} × {q}"); return

        print_fail("Could not factor n.")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()

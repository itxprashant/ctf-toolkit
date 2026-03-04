#!/usr/bin/env python3
"""
rsa_toolkit.py - CTF RSA Attack Toolkit

Automates common RSA attacks used in CTF challenges:
- Wiener's Attack (large d, e is large)
- Fermat's Factorization (p and q are very close)
- Small e (Hastad's Broadcast / Cube Root)
- Common Modulus Attack
"""

import argparse
import itertools
import math
import sys
from typing import Optional, Tuple

try:
    from Crypto.Util.number import inverse, long_to_bytes, GCD
    import gmpy2
    USE_GMPY2 = True
except ImportError:
    USE_GMPY2 = False
    def inverse(u, v):
        """Standard extended Euclidean algorithm for modular inverse"""
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
        """Convert a long integer to a byte string."""
        length = (val.bit_length() + 7) // 8
        return val.to_bytes(length, byteorder=endianness)
    
    def GCD(a, b):
        return math.gcd(a, b)

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


def print_header(title):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 60}\n  {title}\n{'─' * 60}{C.RESET}")

def print_success(msg, detail=None):
    print(f"  {C.GREEN}▶ {msg}{C.RESET}")
    if detail:
        print(f"    {C.YELLOW}{detail}{C.RESET}")

def print_fail(msg):
    print(f"  {C.RED}✗ {msg}{C.RESET}")

def check_flag(msg):
    val = msg.decode('utf-8', errors='ignore')
    if 'flag{' in val.lower() or 'ctf{' in val.lower() or val.isprintable() and len(val) > 4:
        return f"Possible Flag: {val}"
    return None


# ─── Attack: Wiener's Attack ─────────────────────────────────────────────────

def rational_to_contfrac(x, y):
    """Converges a rational number x/y to a continued fraction."""
    a = x // y
    pquotients = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        pquotients.append(a)
    return pquotients

def convergents_from_contfrac(frac):
    """Generates the convergents from a continued fraction."""
    convergents = []
    for i in range(len(frac)):
        convergents.append(contfrac_to_rational(frac[0:i]))
    return convergents

def contfrac_to_rational(frac):
    """Converts a continued fraction to a rational number."""
    if len(frac) == 0: return (0, 1)
    elif len(frac) == 1: return (frac[0], 1)
    n = frac[-1]
    d = 1
    for i in range(2, len(frac)):
        n, d = frac[-i] * n + d, n
    n, d = frac[0] * n + d, n
    return (n, d)

def isqrt(n):
    """Integer square root for Wiener."""
    if USE_GMPY2:
        return int(gmpy2.isqrt(n))
    if n < 0: return -1
    if n == 0: return 0
    x, y = n, (n + 1) // 2
    while y < x:
        x, y = y, (y + n // y) // 2
    return x

def wieners_attack(n, e):
    """Wiener's attack for small d. Returns d if found, else None."""
    frac = rational_to_contfrac(e, n)
    convergents = convergents_from_contfrac(frac)
    
    for (k, d) in convergents:
        if k == 0: continue
        if (e * d - 1) % k != 0: continue
        
        phi = (e * d - 1) // k
        
        # We know n = p*q and phi = (p-1)*(q-1) = n - p - q + 1
        # So p + q = n - phi + 1
        # Roots of x^2 - (p+q)x + pq = 0 are p and q
        s = n - phi + 1
        # check if x^2 - s*x + n = 0 has integer roots
        discriminant = s*s - 4*n
        if discriminant >= 0:
            root = isqrt(discriminant)
            if root * root == discriminant and (s + root) % 2 == 0:
                return d
    return None


# ─── Attack: Fermat's Factorization ──────────────────────────────────────────

def fermats_factorization(n):
    """Fermat's factorization for when p and q are close. Returns (p, q)."""
    a = isqrt(n)
    if a * a == n:
        return a, a
    
    a += 1
    b2 = a*a - n
    b = isqrt(b2)
    count = 0
    
    # Limit iterations to avoid hanging on numbers where p and q aren't close
    max_iter = 1000000 
    
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
    """Find integer x such that x^n <= y."""
    if USE_GMPY2:
        return int(gmpy2.iroot(y, n)[0])
    
    # Binary search approach
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
    """
    If m^e < n, then c = m^e mod n is just c = m^e.
    We just take the e-th root of c.
    """
    m = integer_nth_root(c, e)
    if m**e == c:
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
    """If the same message is encrypted with same n, but coprime e1, e2."""
    g, a, b = extended_gcd(e1, e2)
    if g != 1:
        return None
        
    # We need to compute (c1^a * c2^b) mod n
    # If a < 0, c1^a = (c1^-1)^(-a)
    if a < 0:
        c1 = inverse(c1, n)
        a = -a
    if b < 0:
        c2 = inverse(c2, n)
        b = -b
        
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF RSA Attack Toolkit\nSupports Wiener\'s, Fermat\'s, Small e, and Common Modulus attacks.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    subparsers = parser.add_subparsers(dest='command', help='Attack type')
    
    # ── Standard Single RSA ──
    parser_std = subparsers.add_parser('single', help='Try multiple attacks on a single n, e, c triad')
    parser_std.add_argument('-n', '--modulus', type=lambda x: int(x, 0), required=True, help='Modulus n')
    parser_std.add_argument('-e', '--exponent', type=lambda x: int(x, 0), required=True, help='Public exponent e')
    parser_std.add_argument('-c', '--ciphertext', type=lambda x: int(x, 0), required=True, help='Ciphertext c')
    
    # ── Common Modulus ──
    parser_cm = subparsers.add_parser('common-mod', help='Common Modulus Attack')
    parser_cm.add_argument('-n', type=lambda x: int(x, 0), required=True, help='Common Modulus n')
    parser_cm.add_argument('--e1', type=lambda x: int(x, 0), required=True, help='Exponent 1')
    parser_cm.add_argument('--c1', type=lambda x: int(x, 0), required=True, help='Ciphertext 1')
    parser_cm.add_argument('--e2', type=lambda x: int(x, 0), required=True, help='Exponent 2')
    parser_cm.add_argument('--c2', type=lambda x: int(x, 0), required=True, help='Ciphertext 2')

    args = parser.parse_args()
    
    if not USE_GMPY2:
        print(f"{C.YELLOW}Warning: gmpy2 not installed. Using slower native math.{C.RESET}\n")

    if args.command == 'single':
        n, e, c = args.modulus, args.exponent, args.ciphertext
        print_header("RSA Single-Target Attacks")
        print_field("Modulus (n)", f"{n} ({n.bit_length()} bits)")
        print_field("Exponent (e)", e)
        print_field("Ciphertext (c)", c)
        print()
        
        # 1. Small e / Cube Root Attack
        if e <= 5:
            print(f"  {C.CYAN}Testing Small e (No Padding) Attack...{C.RESET}")
            m = small_e_attack(c, e)
            if m:
                print_success("Small e Attack Succeeded!")
                msg = long_to_bytes(m)
                print_field("Decrypted Integer", m)
                print_field("Decrypted Bytes", msg, C.MAGENTA)
                flag = check_flag(msg)
                if flag: print_success(flag)
                return
            print_fail("Small e Attack failed (message too large or padded).")
            print()

        # 2. Wiener's Attack
        print(f"  {C.CYAN}Testing Wiener's Attack (large d)...{C.RESET}")
        d = wieners_attack(n, e)
        if d:
            print_success("Wiener's Attack Succeeded!")
            print_field("Private Key (d)", d)
            m = pow(c, d, n)
            msg = long_to_bytes(m)
            print_field("Decrypted Bytes", msg, C.MAGENTA)
            flag = check_flag(msg)
            if flag: print_success(flag)
            return
        print_fail("Wiener's Attack failed.")
        print()
        
        # 3. Fermat's Factorization
        print(f"  {C.CYAN}Testing Fermat's Factorization (close p & q)...{C.RESET}")
        p, q = fermats_factorization(n)
        if p and q:
            print_success("Fermat's Factorization Succeeded!")
            print_field("p", p)
            print_field("q", q)
            phi = (p - 1) * (q - 1)
            try:
                d = inverse(e, phi)
                m = pow(c, d, n)
                msg = long_to_bytes(m)
                print_field("Private Key (d)", d)
                print_field("Decrypted Bytes", msg, C.MAGENTA)
                flag = check_flag(msg)
                if flag: print_success(flag)
                return
            except Exception as ex:
                print_fail(f"Could not derive d from p and q: {ex}")
        else:
            print_fail("Fermat's Factorization failed (primes not close enough).")

        print(f"\n{C.RED}All single-target attacks failed.{C.RESET}\n")

    elif args.command == 'common-mod':
        print_header("Common Modulus Attack")
        print_field("Modulus (n)", f"{args.n} ({args.n.bit_length()} bits)")
        print()
        
        m = common_modulus_attack(args.c1, args.c2, args.e1, args.e2, args.n)
        if m is not None:
            print_success("Common Modulus Attack Succeeded!")
            msg = long_to_bytes(m)
            print_field("Decrypted Integer", m)
            print_field("Decrypted Bytes", msg, C.MAGENTA)
            flag = check_flag(msg)
            if flag: print_success(flag)
        else:
            print_fail("Common Modulus Attack failed (exponents not coprime).")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()

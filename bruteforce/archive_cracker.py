#!/usr/bin/env python3
"""
archive_cracker.py - CTF Archive & PDF Password Cracker

Brute force passwords for ZIP and PDF files.
Supports wordlist and brute force modes with progress display.

Usage:
    python3 archive_cracker.py secret.zip --wordlist rockyou.txt
    python3 archive_cracker.py locked.zip --brute --charset digits --max-length 6
    python3 archive_cracker.py encrypted.pdf --wordlist passwords.txt
    python3 archive_cracker.py document.pdf --brute --charset digits --max-length 4
"""

import argparse
import hashlib
import itertools
import os
import string
import struct
import sys
import threading
import time
import zipfile

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


def print_header(text):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 60}")
    print(f"  {text}")
    print(f"{'─' * 60}{C.RESET}")


def print_field(label, value, color=C.GREEN):
    print(f"  {C.BOLD}{label + ':':20s}{C.RESET} {color}{value}{C.RESET}")


# ─── ZIP Cracker ──────────────────────────────────────────────────────────────

def try_zip_password(zip_path, password):
    """Try to extract a ZIP file with the given password."""
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(pwd=password.encode())
            return True
    except (RuntimeError, zipfile.BadZipFile, Exception):
        return False


def get_zip_info(zip_path):
    """Get information about a ZIP archive."""
    info = {}
    try:
        with zipfile.ZipFile(zip_path) as zf:
            info['files'] = len(zf.namelist())
            info['filenames'] = zf.namelist()[:10]
            total_size = sum(zi.file_size for zi in zf.infolist())
            info['total_size'] = total_size
            encrypted = any(zi.flag_bits & 0x1 for zi in zf.infolist())
            info['encrypted'] = encrypted
    except zipfile.BadZipFile:
        info['error'] = 'Invalid ZIP file'
    return info


# ─── PDF Cracker ──────────────────────────────────────────────────────────────

def is_pdf_encrypted(filepath):
    """Check if a PDF file is encrypted."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        return b'/Encrypt' in data
    except Exception:
        return False


def get_pdf_info(filepath):
    """Get info about a PDF file."""
    info = {}
    try:
        with open(filepath, 'rb') as f:
            data = f.read(1024).decode('latin-1', errors='replace')
        # PDF version
        if data.startswith('%PDF-'):
            info['version'] = data[:8].strip()
    except Exception:
        pass

    info['encrypted'] = is_pdf_encrypted(filepath)

    # Detect encryption type
    try:
        with open(filepath, 'rb') as f:
            raw = f.read()
        text = raw.decode('latin-1', errors='replace')

        import re
        # Encryption revision
        rev_match = re.search(r'/R\s+(\d+)', text)
        if rev_match:
            rev = int(rev_match.group(1))
            rev_names = {2: 'RC4 40-bit', 3: 'RC4 128-bit', 4: 'AES-128', 5: 'AES-256'}
            info['encryption'] = rev_names.get(rev, f'Revision {rev}')
            info['revision'] = rev

        # Key length
        length_match = re.search(r'/Length\s+(\d+)', text)
        if length_match:
            info['key_length'] = int(length_match.group(1))

        # Permissions
        perm_match = re.search(r'/P\s+(-?\d+)', text)
        if perm_match:
            info['permissions'] = int(perm_match.group(1))

    except Exception:
        pass

    return info


def try_pdf_password_pikepdf(pdf_path, password):
    """Try to decrypt a PDF with pikepdf."""
    try:
        import pikepdf
        try:
            pdf = pikepdf.open(pdf_path, password=password)
            pdf.close()
            return True
        except pikepdf._core.PasswordError:
            return False
        except Exception:
            return False
    except ImportError:
        return None


def try_pdf_password_pypdf(pdf_path, password):
    """Try to decrypt a PDF with PyPDF2/pypdf."""
    try:
        import pypdf
        try:
            reader = pypdf.PdfReader(pdf_path)
            if reader.is_encrypted:
                result = reader.decrypt(password)
                return result > 0  # 0 = failed, 1 = user password, 2 = owner password
            return True
        except Exception:
            return False
    except ImportError:
        pass

    # Try PyPDF2 as fallback
    try:
        import PyPDF2
        try:
            reader = PyPDF2.PdfReader(pdf_path)
            if reader.is_encrypted:
                result = reader.decrypt(password)
                return result > 0
            return True
        except Exception:
            return False
    except ImportError:
        return None


def get_pdf_try_func(pdf_path):
    """Detect which PDF library is available and return the appropriate try function."""
    # Try pikepdf first (best support)
    result = try_pdf_password_pikepdf(pdf_path, '')
    if result is not None:
        return try_pdf_password_pikepdf, 'pikepdf'

    # Try pypdf / PyPDF2
    result = try_pdf_password_pypdf(pdf_path, '')
    if result is not None:
        return try_pdf_password_pypdf, 'pypdf/PyPDF2'

    return None, None


# ─── Generic Cracking Engine ─────────────────────────────────────────────────

def crack_archive(filepath, try_func, args):
    """Generic cracking engine for any archive type."""
    attempts = 0
    start_time = time.time()
    found = False
    result_password = None
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

    # Wordlist attack
    if args.wordlist:
        for wl_path in args.wordlist:
            if found:
                break
            try:
                with open(wl_path, 'r', errors='replace') as f:
                    for line in f:
                        password = line.strip()
                        if not password:
                            continue
                        attempts += 1
                        if try_func(filepath, password):
                            found = True
                            result_password = password
                            break
            except FileNotFoundError:
                print(f"\n{C.RED}Error: Wordlist '{wl_path}' not found.{C.RESET}")

    # Brute force attack
    if not found and args.brute:
        charset = CHARSETS.get(args.charset, args.charset)
        if args.charset == 'custom' and args.custom_charset:
            charset = args.custom_charset

        for length in range(args.min_length, args.max_length + 1):
            if found:
                break
            for combo in itertools.product(charset, repeat=length):
                password = ''.join(combo)
                attempts += 1
                if try_func(filepath, password):
                    found = True
                    result_password = password
                    break

    stop_progress.set()
    progress_thread.join()
    elapsed = time.time() - start_time
    print()  # Clear progress line

    if found:
        print(f"\n  {C.RED}{C.BOLD}{'═' * 40}")
        print(f"  ⚑ PASSWORD FOUND!")
        print(f"  {'═' * 40}{C.RESET}")
        print(f"  {C.GREEN}{C.BOLD}  File:     {os.path.basename(filepath)}{C.RESET}")
        print(f"  {C.GREEN}{C.BOLD}  Password: {result_password}{C.RESET}")
        print(f"  {C.DIM}  Attempts: {attempts:,} in {elapsed:.2f}s{C.RESET}")
    else:
        print(f"\n  {C.YELLOW}✗ Password not found.{C.RESET}")
        print(f"  {C.DIM}  Attempts: {attempts:,} in {elapsed:.2f}s{C.RESET}")

    print()
    return result_password


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF Archive & PDF Password Cracker — ZIP and PDF brute forcing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s secret.zip --wordlist rockyou.txt
  %(prog)s locked.zip --brute --charset digits --max-length 4
  %(prog)s encrypted.pdf --wordlist passwords.txt
  %(prog)s document.pdf --brute --charset digits --max-length 6
  %(prog)s archive.zip --wordlist list1.txt --wordlist list2.txt

Supported formats:
  ZIP — uses Python stdlib (no extra dependencies)
  PDF — uses pikepdf, pypdf, or PyPDF2 (install one):
        pip install pikepdf   (recommended, best compatibility)
        pip install pypdf     (lightweight alternative)
        """
    )
    parser.add_argument('file', help='File to crack (ZIP or PDF)')
    parser.add_argument('--wordlist', '-w', type=str, action='append',
                        help='Wordlist file(s) to use')
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

    if not os.path.isfile(args.file):
        print(f"{C.RED}Error: '{args.file}' not found.{C.RESET}", file=sys.stderr)
        sys.exit(1)

    if not args.wordlist and not args.brute:
        parser.error('Specify --wordlist and/or --brute')

    filepath = args.file

    # Detect file type
    with open(filepath, 'rb') as f:
        magic = f.read(8)

    if magic[:4] == b'PK\x03\x04' or magic[:4] == b'PK\x05\x06':
        # ── ZIP ───────────────────────────────────────────────────────────
        info = get_zip_info(filepath)
        print_header(f"ZIP Cracker: {os.path.basename(filepath)}")
        print_field('Files', str(info.get('files', '?')))
        if info.get('filenames'):
            for fn in info['filenames'][:5]:
                print(f"  {C.DIM}  └ {fn}{C.RESET}")
            if info.get('files', 0) > 5:
                print(f"  {C.DIM}  └ ... and {info['files'] - 5} more{C.RESET}")
        print_field('Encrypted', str(info.get('encrypted', '?')))

        if not info.get('encrypted'):
            print(f"\n  {C.YELLOW}⚠ ZIP does not appear to be encrypted!{C.RESET}\n")
            return

        crack_archive(filepath, try_zip_password, args)

    elif magic[:5] == b'%PDF-':
        # ── PDF ───────────────────────────────────────────────────────────
        pdf_info = get_pdf_info(filepath)
        print_header(f"PDF Cracker: {os.path.basename(filepath)}")

        if pdf_info.get('version'):
            print_field('Version', pdf_info['version'])
        if pdf_info.get('encryption'):
            print_field('Encryption', pdf_info['encryption'])
        if pdf_info.get('key_length'):
            print_field('Key Length', f"{pdf_info['key_length']} bits")
        print_field('Encrypted', str(pdf_info.get('encrypted', False)))

        if not pdf_info.get('encrypted'):
            print(f"\n  {C.YELLOW}⚠ PDF does not appear to be encrypted!{C.RESET}\n")
            return

        # Find a working PDF library
        try_func, lib_name = get_pdf_try_func(filepath)
        if try_func is None:
            print(f"\n  {C.RED}Error: No PDF library found. Install one of:{C.RESET}")
            print(f"  {C.DIM}  pip install pikepdf    (recommended){C.RESET}")
            print(f"  {C.DIM}  pip install pypdf      (lightweight){C.RESET}")
            print(f"  {C.DIM}  pip install PyPDF2     (legacy){C.RESET}\n")
            sys.exit(1)

        print_field('PDF Library', lib_name)

        # Try empty password first
        if try_func(filepath, ''):
            print(f"\n  {C.GREEN}{C.BOLD}⚑ PDF opens with empty password!{C.RESET}")
            print(f"  {C.DIM}  The PDF has an owner password but no user password.{C.RESET}\n")
            return

        crack_archive(filepath, try_func, args)

    else:
        magic_hex = ' '.join(f'{b:02x}' for b in magic[:8])
        print(f"{C.RED}Error: Unsupported file type (magic: {magic_hex}).{C.RESET}")
        print(f"{C.DIM}Supported: ZIP, PDF{C.RESET}")
        sys.exit(1)


if __name__ == '__main__':
    main()

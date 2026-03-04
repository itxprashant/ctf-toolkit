#!/usr/bin/env python3
"""
wordlist_gen.py - CTF Wordlist Generator & Mutator

Generate custom wordlists from patterns, base words, or character sets.
Apply mutation rules for password spraying in CTF challenges.

Usage:
    python3 wordlist_gen.py --base-words admin,password,flag --rules --output wordlist.txt
    python3 wordlist_gen.py --pattern 'CTF{####}' --output pins.txt
    python3 wordlist_gen.py --charset digits --min-length 4 --max-length 6 --output numeric.txt
    python3 wordlist_gen.py --combine words.txt --with-suffixes 1,123,! --output combined.txt
"""

import argparse
import itertools
import os
import string
import sys

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
    'hex':      '0123456789abcdef',
    'special':  string.punctuation,
    'all':      string.ascii_letters + string.digits + string.punctuation,
}


def print_header(text):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 60}", file=sys.stderr)
    print(f"  {text}", file=sys.stderr)
    print(f"{'─' * 60}{C.RESET}", file=sys.stderr)


def print_field(label, value, color=C.GREEN):
    print(f"  {C.BOLD}{label + ':':20s}{C.RESET} {color}{value}{C.RESET}", file=sys.stderr)


# ─── Mutation Rules ──────────────────────────────────────────────────────────

LEET_MAP = {
    'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'],
    'o': ['0'],  's': ['$', '5'], 't': ['7'],
    'l': ['1'], 'g': ['9'], 'b': ['8'],
}

COMMON_SUFFIXES = [
    '', '1', '2', '3', '12', '123', '1234', '!', '!!', '@',
    '#', '01', '69', '99', '00', '007', '2024', '2025', '2026',
    '!@#', '_', '.', '0', '11', '22', '666', '777', '888',
]

COMMON_PREFIXES = ['', '!', '@', '#', '123', 'the', 'my']


def mutate_word(word, level='basic'):
    """Generate mutations of a word at different intensity levels."""
    mutations = set()
    mutations.add(word)

    # Basic mutations (always applied)
    mutations.add(word.lower())
    mutations.add(word.upper())
    mutations.add(word.capitalize())
    mutations.add(word.swapcase())
    mutations.add(word.title())

    # Reversed
    mutations.add(word[::-1])
    mutations.add(word[::-1].capitalize())

    if level in ('medium', 'full'):
        # Suffix mutations
        for suffix in COMMON_SUFFIXES:
            mutations.add(word + suffix)
            mutations.add(word.capitalize() + suffix)
            mutations.add(word.upper() + suffix)

        # Prefix mutations
        for prefix in COMMON_PREFIXES:
            mutations.add(prefix + word)
            mutations.add(prefix + word.capitalize())

    if level == 'full':
        # Leet speak — single-pass replacement
        leet = list(word.lower())
        for i, ch in enumerate(leet):
            if ch in LEET_MAP:
                leet[i] = LEET_MAP[ch][0]
        leet_word = ''.join(leet)
        mutations.add(leet_word)
        mutations.add(leet_word.capitalize() if leet_word else leet_word)

        for suffix in COMMON_SUFFIXES[:10]:
            mutations.add(leet_word + suffix)

        # Double the word
        mutations.add(word + word)
        mutations.add(word.capitalize() + word.capitalize())

        # First + last char uppercase
        if len(word) > 1:
            mutations.add(word[0].upper() + word[1:])
            mutations.add(word[:-1] + word[-1].upper())

    return sorted(mutations)


# ─── Pattern Generator ───────────────────────────────────────────────────────

def generate_from_pattern(pattern):
    """
    Generate words from a pattern with placeholders:
      # = digit (0-9)
      ? = lowercase letter
      ^ = uppercase letter
      * = alphanumeric
      Literal characters are kept as-is
    """
    placeholder_map = {
        '#': string.digits,
        '?': string.ascii_lowercase,
        '^': string.ascii_uppercase,
        '*': string.ascii_letters + string.digits,
    }

    positions = []
    for ch in pattern:
        if ch in placeholder_map:
            positions.append(placeholder_map[ch])
        else:
            positions.append(ch)

    # Calculate total combinations
    total = 1
    for p in positions:
        total *= len(p)

    for combo in itertools.product(*positions):
        yield ''.join(combo)


# ─── Combination Generator ───────────────────────────────────────────────────

def combine_with_modifications(words, suffixes=None, prefixes=None):
    """Combine base words with suffixes and prefixes."""
    if suffixes is None:
        suffixes = ['']
    if prefixes is None:
        prefixes = ['']

    for word in words:
        for prefix in prefixes:
            for suffix in suffixes:
                yield prefix + word + suffix
                if word != word.capitalize():
                    yield prefix + word.capitalize() + suffix


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF Wordlist Generator — patterns, mutations, combinations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  --base-words   Generate mutations of given words
  --pattern      Generate from pattern (# digit, ? lower, ^ upper, * alnum)
  --charset      Brute-force all combinations of a character set
  --combine      Read words from file and combine with suffixes/prefixes

Examples:
  %(prog)s --base-words admin,root,flag --rules full --output out.txt
  %(prog)s --pattern 'flag{####}' --output flags.txt
  %(prog)s --pattern 'CTF{??##}' --output combos.txt
  %(prog)s --charset digits --min-length 4 --max-length 4 --output pins.txt
  %(prog)s --combine words.txt --with-suffixes '1,123,!' --output combined.txt
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--base-words', '-B', type=str,
                      help='Comma-separated base words to mutate')
    mode.add_argument('--pattern', '-P', type=str,
                      help='Pattern with placeholders (# ? ^ *)')
    mode.add_argument('--charset', '-C', type=str, choices=list(CHARSETS.keys()),
                      help='Generate all combinations from charset')
    mode.add_argument('--combine', type=str,
                      help='Wordlist file to combine with suffixes/prefixes')

    parser.add_argument('--rules', '-r', type=str, default='basic',
                        choices=['basic', 'medium', 'full'],
                        help='Mutation level for --base-words (default: basic)')
    parser.add_argument('--with-suffixes', type=str,
                        help='Comma-separated suffixes for --combine')
    parser.add_argument('--with-prefixes', type=str,
                        help='Comma-separated prefixes for --combine')
    parser.add_argument('--min-length', type=int, default=1,
                        help='Min length for --charset (default: 1)')
    parser.add_argument('--max-length', '-m', type=int, default=4,
                        help='Max length for --charset (default: 4)')
    parser.add_argument('--output', '-o', type=str,
                        help='Output file (default: stdout)')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    output_file = None
    if args.output:
        output_file = open(args.output, 'w')

    count = 0

    def emit(word):
        nonlocal count
        count += 1
        if output_file:
            output_file.write(word + '\n')
        else:
            print(word)

    # ── Base Words Mode ───────────────────────────────────────────────────
    if args.base_words:
        words = [w.strip() for w in args.base_words.split(',') if w.strip()]
        print_header(f"Wordlist Generator: base-words mode")
        print_field('Base Words', str(len(words)))
        print_field('Mutation Level', args.rules)

        seen = set()
        for word in words:
            for mutation in mutate_word(word, args.rules):
                if mutation not in seen:
                    seen.add(mutation)
                    emit(mutation)

    # ── Pattern Mode ──────────────────────────────────────────────────────
    elif args.pattern:
        print_header(f"Wordlist Generator: pattern mode")
        print_field('Pattern', args.pattern)

        # Estimate size
        total = 1
        for ch in args.pattern:
            if ch == '#': total *= 10
            elif ch == '?': total *= 26
            elif ch == '^': total *= 26
            elif ch == '*': total *= 62

        print_field('Estimated Count', f'{total:,}')

        for word in generate_from_pattern(args.pattern):
            emit(word)

    # ── Charset Mode ──────────────────────────────────────────────────────
    elif args.charset:
        charset = CHARSETS[args.charset]
        print_header(f"Wordlist Generator: charset mode")
        print_field('Charset', f'{args.charset} ({len(charset)} chars)')
        print_field('Length Range', f'{args.min_length}-{args.max_length}')

        total = sum(len(charset) ** l for l in range(args.min_length, args.max_length + 1))
        print_field('Total Combinations', f'{total:,}')

        for length in range(args.min_length, args.max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                emit(''.join(combo))

    # ── Combine Mode ──────────────────────────────────────────────────────
    elif args.combine:
        print_header(f"Wordlist Generator: combine mode")
        print_field('Source', args.combine)

        try:
            with open(args.combine) as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{C.RED}Error: '{args.combine}' not found.{C.RESET}", file=sys.stderr)
            sys.exit(1)

        suffixes = args.with_suffixes.split(',') if args.with_suffixes else ['']
        prefixes = args.with_prefixes.split(',') if args.with_prefixes else ['']

        print_field('Words', str(len(words)))
        print_field('Suffixes', str(suffixes))
        print_field('Prefixes', str(prefixes))

        seen = set()
        for word in combine_with_modifications(words, suffixes, prefixes):
            if word not in seen:
                seen.add(word)
                emit(word)

    # Summary
    print_field('Generated', f'{count:,} passwords')
    if args.output:
        print_field('Saved To', args.output)
        output_file.close()

    print(file=sys.stderr)


if __name__ == '__main__':
    main()

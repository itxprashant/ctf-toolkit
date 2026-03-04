#!/usr/bin/env python3
"""
cipher_solver.py - Classical Cipher Solver Toolkit

Automates cracking of historical ciphers commonly found in CTF challenges:
- Caesar Cipher (brute forces all 25 shifts)
- ROT13 / ROT47 (special-case rotations)
- Atbash (mirror substitution)
- Affine Cipher (brute-force all valid ax+b pairs)
- Vigenère Cipher (determines key length via Index of Coincidence)
- Rail Fence Cipher (brute-force rail counts)
- Substitution Cipher (frequency-analysis mapping)
- Morse Code (dot-dash / binary decoding)
- Base Encoding Detection (Base16/32/64/85 auto-detect)
- Baconian Cipher (5-bit A/B binary encoding)
- Auto-detect mode (heuristic cipher identification)
"""

import argparse
import sys
import re
import base64
from math import gcd
from collections import Counter


# ANSI colors
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# English letter frequencies
ENGLISH_FREQS = {
    "A": 0.08167,
    "B": 0.01492,
    "C": 0.02782,
    "D": 0.04253,
    "E": 0.12702,
    "F": 0.02228,
    "G": 0.02015,
    "H": 0.06094,
    "I": 0.06966,
    "J": 0.00015,
    "K": 0.00772,
    "L": 0.04025,
    "M": 0.02406,
    "N": 0.06749,
    "O": 0.07507,
    "P": 0.01929,
    "Q": 0.00095,
    "R": 0.05987,
    "S": 0.06327,
    "T": 0.09056,
    "U": 0.02758,
    "V": 0.00978,
    "W": 0.02360,
    "X": 0.00150,
    "Y": 0.01974,
    "Z": 0.00074,
}

# Frequency-ordered English letters (most to least common)
ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

# ─── Dictionary for validation ───────────────────────────────────────────────

# Compact English word list for scoring decryptions.
# Includes common short words, CTF-relevant terms, and high-frequency words.
COMMON_WORDS = {
    "the",
    "be",
    "to",
    "of",
    "and",
    "a",
    "in",
    "that",
    "have",
    "i",
    "it",
    "for",
    "not",
    "on",
    "with",
    "he",
    "as",
    "you",
    "do",
    "at",
    "this",
    "but",
    "his",
    "by",
    "from",
    "they",
    "we",
    "say",
    "her",
    "she",
    "or",
    "an",
    "will",
    "my",
    "one",
    "all",
    "would",
    "there",
    "their",
    "what",
    "so",
    "up",
    "out",
    "if",
    "about",
    "who",
    "get",
    "which",
    "go",
    "me",
    "when",
    "make",
    "can",
    "like",
    "time",
    "no",
    "just",
    "him",
    "know",
    "take",
    "people",
    "into",
    "year",
    "your",
    "good",
    "some",
    "could",
    "them",
    "see",
    "other",
    "than",
    "then",
    "now",
    "look",
    "only",
    "come",
    "its",
    "over",
    "think",
    "also",
    "back",
    "after",
    "use",
    "two",
    "how",
    "our",
    "work",
    "first",
    "well",
    "way",
    "even",
    "new",
    "want",
    "because",
    "any",
    "these",
    "give",
    "day",
    "most",
    "us",
    "is",
    "are",
    "was",
    "were",
    "been",
    "has",
    "had",
    "did",
    "does",
    "may",
    "must",
    "should",
    "shall",
    "here",
    "where",
    "very",
    "more",
    "much",
    "too",
    "every",
    "still",
    "never",
    "always",
    "before",
    "while",
    "since",
    "each",
    "many",
    "such",
    "between",
    "through",
    "same",
    "under",
    "last",
    "long",
    "great",
    "little",
    "own",
    "old",
    "right",
    "big",
    "high",
    "different",
    "small",
    "large",
    "next",
    "early",
    "young",
    "important",
    "few",
    "public",
    "bad",
    "same",
    "able",
    # CTF-relevant words
    "flag",
    "ctf",
    "key",
    "secret",
    "hidden",
    "password",
    "crypto",
    "cipher",
    "decode",
    "encrypt",
    "decrypt",
    "hash",
    "code",
    "message",
    "text",
    "attack",
    "capture",
    "security",
    "hack",
    "exploit",
    "solve",
    "answer",
    "challenge",
    "congratulations",
    "correct",
    "found",
    "well",
    "done",
    "submit",
    "bravo",
    "winner",
}


# ─── Utility Functions ───────────────────────────────────────────────────────


def clean_text(text):
    """Keep only alphabetic uppercase characters."""
    return re.sub(r"[^A-Z]", "", text.upper())


def check_flag(text):
    """Highlight if text looks like a flag."""
    upper = text.upper()
    return "FLAG" in upper or "CTF" in upper


def score_text(text):
    """Score text based on English letter frequency (Chi-squared)."""
    cleaned = clean_text(text)
    if not cleaned:
        return float("inf")

    counts = Counter(cleaned)
    length = len(cleaned)

    chi_sq = 0.0
    for char, expected_pct in ENGLISH_FREQS.items():
        expected = length * expected_pct
        actual = counts.get(char, 0)
        if expected > 0:
            chi_sq += ((actual - expected) ** 2) / expected

    return chi_sq


def score_text_dict(text):
    """Score text by counting common English words found in it."""
    words = re.findall(r"[a-zA-Z]+", text.lower())
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in COMMON_WORDS)
    return hits / len(words)


def combined_score(text):
    """
    Combined scoring: lower is better.
    Blends Chi-squared (lower = more English-like) with dictionary hits (higher = better).
    The dict score is inverted and scaled so that it reduces the Chi-squared score.
    """
    chi = score_text(text)
    dict_ratio = score_text_dict(text)
    # dict_ratio is 0..1; multiply by a weight to meaningfully influence the chi score
    # A high dict_ratio (many real words) should significantly lower the combined score
    return chi * (1.0 - 0.5 * dict_ratio)


def excerpt_text(text, max_len=150):
    """Truncate text for display."""
    return text[:max_len] + "..." if len(text) > max_len else text


def mod_inverse(a, m):
    """Compute modular multiplicative inverse of a mod m using extended Euclidean algorithm."""
    if gcd(a, m) != 1:
        return None
    # Extended Euclidean
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        return None
    return x % m


def _extended_gcd(a, b):
    """Extended Euclidean algorithm. Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


# ─── Caesar Cipher ───────────────────────────────────────────────────────────


def decrypt_caesar(text, shift):
    """Decrypt text using a specific Caesar shift."""
    result = []
    for char in text:
        if char.isupper():
            result.append(chr(((ord(char) - ord("A") - shift) % 26) + ord("A")))
        elif char.islower():
            result.append(chr(((ord(char) - ord("a") - shift) % 26) + ord("a")))
        else:
            result.append(char)
    return "".join(result)


def solve_caesar(text):
    """Try all 25 shifts and score them."""
    results = []
    for shift in range(1, 26):
        plaintext = decrypt_caesar(text, shift)
        score = combined_score(plaintext)
        results.append((score, shift, plaintext))

    results.sort(key=lambda x: x[0])
    return results[:5]


# ─── ROT13 / ROT47 ──────────────────────────────────────────────────────────


def solve_rot13(text):
    """Decrypt ROT13 (Caesar shift of 13)."""
    return decrypt_caesar(text, 13)


def solve_rot47(text):
    """Decrypt ROT47 - rotates all printable ASCII characters (33-126) by 47."""
    result = []
    for char in text:
        code = ord(char)
        if 33 <= code <= 126:
            result.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            result.append(char)
    return "".join(result)


# ─── Atbash Cipher ───────────────────────────────────────────────────────────


def solve_atbash(text):
    """Decrypt using Atbash (A->Z, B->Y, etc)."""
    result = []
    for char in text:
        if char.isupper():
            result.append(chr(ord("Z") - (ord(char) - ord("A"))))
        elif char.islower():
            result.append(chr(ord("z") - (ord(char) - ord("a"))))
        else:
            result.append(char)
    return "".join(result)


# ─── Affine Cipher ───────────────────────────────────────────────────────────

# Valid 'a' values (coprime with 26)
AFFINE_A_VALUES = [a for a in range(1, 26) if gcd(a, 26) == 1]
# => [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]


def decrypt_affine(text, a, b):
    """Decrypt text encrypted with affine cipher E(x) = (a*x + b) mod 26."""
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return None

    result = []
    for char in text:
        if char.isupper():
            x = ord(char) - ord("A")
            result.append(chr(((a_inv * (x - b)) % 26) + ord("A")))
        elif char.islower():
            x = ord(char) - ord("a")
            result.append(chr(((a_inv * (x - b)) % 26) + ord("a")))
        else:
            result.append(char)
    return "".join(result)


def solve_affine(text):
    """Brute-force all valid (a, b) pairs and score results."""
    results = []
    for a in AFFINE_A_VALUES:
        for b in range(26):
            plaintext = decrypt_affine(text, a, b)
            if plaintext is None:
                continue
            score = combined_score(plaintext)
            results.append((score, a, b, plaintext))

    results.sort(key=lambda x: x[0])
    return results[:5]


# ─── Vigenère Cipher ─────────────────────────────────────────────────────────


def calculate_ioc(text):
    """Calculate Index of Coincidence for a string."""
    cleaned = clean_text(text)
    if len(cleaned) < 2:
        return 0.0

    counts = Counter(cleaned)
    ioc = 0.0
    n = len(cleaned)
    for count in counts.values():
        ioc += count * (count - 1)
    return ioc / (n * (n - 1))


def find_vigenere_key_length(text, max_len=20):
    """Find most probable key lengths using Index of Coincidence."""
    cleaned = clean_text(text)
    if not cleaned:
        return []

    iocs = []
    for length in range(2, min(max_len + 1, len(cleaned) // 2)):
        avg_ioc = 0.0
        for i in range(length):
            substring = cleaned[i::length]
            avg_ioc += calculate_ioc(substring)
        avg_ioc /= length
        iocs.append((avg_ioc, length))

    # Sort by closeness to English IoC (reverse order to get highest IoC)
    iocs.sort(key=lambda x: x[0], reverse=True)
    return [l for _, l in iocs[:3]]


def decrypt_vigenere(text, key_str):
    """Decrypt Vigenère cipher with a given key, preserving non-alpha characters."""
    key_str = key_str.upper()
    key_len = len(key_str)
    result = []
    key_idx = 0
    for char in text:
        if char.isalpha():
            shift = ord(key_str[key_idx % key_len]) - ord("A")
            if char.isupper():
                result.append(chr(((ord(char) - ord("A") - shift) % 26) + ord("A")))
            else:
                result.append(chr(((ord(char) - ord("a") - shift) % 26) + ord("a")))
            key_idx += 1
        else:
            result.append(char)
    return "".join(result)


def solve_vigenere_with_length(text, key_len):
    """Break Vigenère cipher given a specific key length."""
    cleaned = clean_text(text)
    if not cleaned:
        return None, None

    key = []
    # Solve each column as a Caesar shift
    for i in range(key_len):
        substring = cleaned[i::key_len]

        # Test all 26 shifts for this column
        best_shift = 0
        best_score = float("inf")
        for shift in range(26):
            shifted_sub = decrypt_caesar(substring, shift)
            score = score_text(shifted_sub)
            if score < best_score:
                best_score = score
                best_shift = shift

        key.append(chr(best_shift + ord("A")))

    key_str = "".join(key)
    plaintext = decrypt_vigenere(text, key_str)
    return key_str, plaintext


def solve_vigenere(text):
    """Automatically find key length and solve Vigenère."""
    lengths = find_vigenere_key_length(text)
    results = []
    for length in lengths:
        key, plaintext = solve_vigenere_with_length(text, length)
        if key:
            score = combined_score(plaintext)
            results.append((score, length, key, plaintext))

    results.sort(key=lambda x: x[0])
    return results


# ─── Rail Fence Cipher ───────────────────────────────────────────────────────


def decrypt_railfence(text, rails):
    """Decrypt a rail fence cipher with a given number of rails."""
    if rails < 2 or rails >= len(text):
        return text

    n = len(text)
    # Build the zigzag pattern to determine which characters go to which rail
    pattern = []
    for i in range(n):
        cycle = 2 * (rails - 1)
        pos = i % cycle
        rail = pos if pos < rails else cycle - pos
        pattern.append(rail)

    # Count characters per rail
    rail_lengths = [0] * rails
    for r in pattern:
        rail_lengths[r] += 1

    # Split ciphertext into rails
    rail_texts = []
    idx = 0
    for r in range(rails):
        rail_texts.append(text[idx : idx + rail_lengths[r]])
        idx += rail_lengths[r]

    # Read off in zigzag order
    rail_indices = [0] * rails
    result = []
    for r in pattern:
        result.append(rail_texts[r][rail_indices[r]])
        rail_indices[r] += 1

    return "".join(result)


def solve_railfence(text):
    """Try all rail counts from 2 to min(20, len/2) and score results."""
    results = []
    max_rails = min(20, len(text) // 2)
    for rails in range(2, max_rails + 1):
        plaintext = decrypt_railfence(text, rails)
        score = combined_score(plaintext)
        results.append((score, rails, plaintext))

    results.sort(key=lambda x: x[0])
    return results[:5]


# ─── Substitution Cipher ────────────────────────────────────────────────────


def solve_substitution(text):
    """
    Frequency-analysis-based substitution cipher solver.
    Maps most frequent ciphertext letters to most frequent English letters.
    Returns the mapping and decrypted text.
    """
    cleaned = clean_text(text)
    if not cleaned:
        return None, None, text

    # Count frequencies in ciphertext
    counts = Counter(cleaned)
    # Sort by frequency (most common first)
    cipher_freq_order = [char for char, _ in counts.most_common()]

    # Build mapping: most frequent cipher letter -> E, second -> T, etc.
    mapping = {}
    for i, cipher_char in enumerate(cipher_freq_order):
        if i < len(ENGLISH_FREQ_ORDER):
            mapping[cipher_char] = ENGLISH_FREQ_ORDER[i]

    # Apply mapping, preserving case and non-alpha characters
    result = []
    for char in text:
        if char.upper() in mapping:
            mapped = mapping[char.upper()]
            result.append(mapped.lower() if char.islower() else mapped)
        elif char.isalpha():
            # Unmapped letter (shouldn't happen if text has all 26 letters)
            result.append(char)
        else:
            result.append(char)

    return mapping, cipher_freq_order, "".join(result)


# ─── Morse Code ──────────────────────────────────────────────────────────────

MORSE_TO_ALPHA = {
    ".-": "A",
    "-...": "B",
    "-.-.": "C",
    "-..": "D",
    ".": "E",
    "..-.": "F",
    "--.": "G",
    "....": "H",
    "..": "I",
    ".---": "J",
    "-.-": "K",
    ".-..": "L",
    "--": "M",
    "-.": "N",
    "---": "O",
    ".--.": "P",
    "--.-": "Q",
    ".-.": "R",
    "...": "S",
    "-": "T",
    "..-": "U",
    "...-": "V",
    ".--": "W",
    "-..-": "X",
    "-.--": "Y",
    "--..": "Z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
}


def solve_morse(text):
    """
    Decode Morse code from various formats:
    - Standard: .- -... -.-. (space-separated, / for word breaks)
    - Unicode: using · and − instead of . and -
    - Binary: 0=dot, 1=dash with spaces
    """
    # Normalize unicode variants
    normalized = text.replace("·", ".").replace("−", "-").replace("–", "-")
    # Normalize word separators
    normalized = re.sub(r"\s*[/|]\s*", " / ", normalized)

    # Try binary morse (0=dot, 1=dash) if input looks binary-ish
    if re.match(r"^[01\s/|]+$", text.strip()):
        normalized = text.replace("0", ".").replace("1", "-")
        normalized = re.sub(r"\s*[/|]\s*", " / ", normalized)

    # Split by word separators
    words = re.split(r"\s*/\s*", normalized)

    decoded_words = []
    for word in words:
        letters = word.strip().split()
        decoded_letters = []
        for letter in letters:
            letter = letter.strip()
            if letter in MORSE_TO_ALPHA:
                decoded_letters.append(MORSE_TO_ALPHA[letter])
            elif letter:
                decoded_letters.append("?")
        if decoded_letters:
            decoded_words.append("".join(decoded_letters))

    return " ".join(decoded_words)


# ─── Base Encoding Detection ────────────────────────────────────────────────


def _try_decode(func, text):
    """Try a base decoding function, return decoded string or None."""
    try:
        decoded = func(text.encode("ascii"))
        result = decoded.decode("utf-8", errors="strict")
        # Check if result is mostly printable
        printable_ratio = sum(
            1 for c in result if c.isprintable() or c.isspace()
        ) / max(len(result), 1)
        if printable_ratio > 0.8 and len(result) > 0:
            return result
    except Exception:
        pass
    return None


def solve_base_encodings(text):
    """Try decoding input as various base encodings. Returns list of (encoding_name, decoded_text)."""
    results = []
    stripped = text.strip()

    # Base64 - try with padding fix
    for candidate in [stripped, stripped + "=", stripped + "=="]:
        decoded = _try_decode(base64.b64decode, candidate)
        if decoded:
            results.append(("Base64", decoded))
            break

    # Base32 - try with padding fix
    upper = stripped.upper()
    for candidate in [
        upper,
        upper + "=",
        upper + "==",
        upper + "===",
        upper + "====",
        upper + "=====",
        upper + "======",
    ]:
        decoded = _try_decode(base64.b32decode, candidate)
        if decoded:
            results.append(("Base32", decoded))
            break

    # Base16 (hex)
    hex_clean = re.sub(r"[^0-9a-fA-F]", "", stripped)
    if len(hex_clean) >= 2 and len(hex_clean) % 2 == 0:
        decoded = _try_decode(base64.b16decode, hex_clean.upper())
        if decoded:
            results.append(("Base16/Hex", decoded))

    # Base85 (ASCII85)
    decoded = _try_decode(base64.b85decode, stripped)
    if decoded:
        results.append(("Base85", decoded))

    # Also try ascii85 (Adobe variant)
    decoded = _try_decode(base64.a85decode, stripped)
    if decoded:
        results.append(("ASCII85", decoded))

    return results


# ─── Baconian Cipher ─────────────────────────────────────────────────────────

# Standard Bacon cipher (I=J, U=V: 24 letters mapped to 5-bit codes)
BACON_STANDARD = {
    "AAAAA": "A",
    "AAAAB": "B",
    "AAABA": "C",
    "AAABB": "D",
    "AABAA": "E",
    "AABAB": "F",
    "AABBA": "G",
    "AABBB": "H",
    "ABAAA": "I",
    "ABAAB": "K",
    "ABABA": "L",
    "ABABB": "M",
    "ABBAA": "N",
    "ABBAB": "O",
    "ABBBA": "P",
    "ABBBB": "Q",
    "BAAAA": "R",
    "BAAAB": "S",
    "BAABA": "T",
    "BAABB": "U",
    "BABAA": "W",
    "BABAB": "X",
    "BABBA": "Y",
    "BABBB": "Z",
}

# Full 26-letter Bacon cipher
BACON_FULL = {
    "AAAAA": "A",
    "AAAAB": "B",
    "AAABA": "C",
    "AAABB": "D",
    "AABAA": "E",
    "AABAB": "F",
    "AABBA": "G",
    "AABBB": "H",
    "ABAAA": "I",
    "ABAAB": "J",
    "ABABA": "K",
    "ABABB": "L",
    "ABBAA": "M",
    "ABBAB": "N",
    "ABBBA": "O",
    "ABBBB": "P",
    "BAAAA": "Q",
    "BAAAB": "R",
    "BAABA": "S",
    "BAABB": "T",
    "BABAA": "U",
    "BABAB": "V",
    "BABBA": "W",
    "BABBB": "X",
    "BAAAA": "Y",
    "BAAAB": "Z",
}
# Note: Full 26-letter has collisions in some historical variants; this uses
# the most common assignment. For a true distinct-26 mapping:
BACON_FULL_26 = {}
for i in range(26):
    bits = format(i, "05b").replace("0", "A").replace("1", "B")
    BACON_FULL_26[bits] = chr(ord("A") + i)


def solve_bacon(text):
    """
    Decode Baconian cipher from various input formats:
    - A/B strings: 'AABBA AABAB ...'
    - 0/1 binary: '00110 00101 ...'
    - Case-based: lowercase=A, UPPERCASE=B (or vice versa)
    """
    results = []

    # Strategy 1: Input is already A/B (with optional spaces)
    ab_clean = re.sub(r"[^ABab]", "", text.upper())
    if len(ab_clean) >= 5:
        for label, table in [
            ("Standard (I=J, U=V)", BACON_STANDARD),
            ("Full 26-letter", BACON_FULL_26),
        ]:
            decoded = []
            for i in range(0, len(ab_clean) - 4, 5):
                chunk = ab_clean[i : i + 5]
                decoded.append(table.get(chunk, "?"))
            result = "".join(decoded)
            if "?" not in result or result.count("?") < len(result) // 2:
                results.append((f"A/B {label}", result))

    # Strategy 2: Input is binary 0/1
    bin_clean = re.sub(r"[^01]", "", text)
    if len(bin_clean) >= 5:
        ab_from_bin = bin_clean.replace("0", "A").replace("1", "B")
        for label, table in [
            ("Standard (I=J, U=V)", BACON_STANDARD),
            ("Full 26-letter", BACON_FULL_26),
        ]:
            decoded = []
            for i in range(0, len(ab_from_bin) - 4, 5):
                chunk = ab_from_bin[i : i + 5]
                decoded.append(table.get(chunk, "?"))
            result = "".join(decoded)
            if "?" not in result or result.count("?") < len(result) // 2:
                results.append((f"Binary {label}", result))

    # Strategy 3: Case-based (lowercase=A, uppercase=B)
    alpha_only = re.sub(r"[^a-zA-Z]", "", text)
    if len(alpha_only) >= 5:
        # lowercase=A, uppercase=B
        case_ab = "".join("A" if c.islower() else "B" for c in alpha_only)
        for label, table in [
            ("Standard (I=J, U=V)", BACON_STANDARD),
            ("Full 26-letter", BACON_FULL_26),
        ]:
            decoded = []
            for i in range(0, len(case_ab) - 4, 5):
                chunk = case_ab[i : i + 5]
                decoded.append(table.get(chunk, "?"))
            result = "".join(decoded)
            if "?" not in result or result.count("?") < len(result) // 2:
                results.append((f"Case(lower=A) {label}", result))

        # Also try: uppercase=A, lowercase=B
        case_ab_inv = "".join("B" if c.islower() else "A" for c in alpha_only)
        for label, table in [
            ("Standard (I=J, U=V)", BACON_STANDARD),
            ("Full 26-letter", BACON_FULL_26),
        ]:
            decoded = []
            for i in range(0, len(case_ab_inv) - 4, 5):
                chunk = case_ab_inv[i : i + 5]
                decoded.append(table.get(chunk, "?"))
            result = "".join(decoded)
            if "?" not in result or result.count("?") < len(result) // 2:
                results.append((f"Case(upper=A) {label}", result))

    return results


# ─── Auto-detect Mode ────────────────────────────────────────────────────────


def detect_cipher(text):
    """
    Analyze input and suggest which cipher(s) were likely used.
    Returns a list of (cipher_name, confidence, description) tuples sorted by confidence.
    """
    suggestions = []
    stripped = text.strip()

    # Check for Morse code patterns
    if re.match(r"^[\.\-·−–\s/|01]+$", stripped) and len(stripped) > 3:
        if "." in stripped or "-" in stripped or "·" in stripped or "−" in stripped:
            suggestions.append(
                ("morse", 0.95, "Input contains dots/dashes typical of Morse code")
            )
        elif re.match(r"^[01\s/|]+$", stripped):
            suggestions.append(
                ("morse", 0.7, "Binary input could be Morse (0=dot, 1=dash)")
            )

    # Check for Base64 pattern
    if re.match(r"^[A-Za-z0-9+/]+=*$", stripped) and len(stripped) >= 4:
        if len(stripped) % 4 <= 2:  # valid Base64 padding
            suggestions.append(("base", 0.8, "Input matches Base64 character set"))

    # Check for hex pattern
    if re.match(r"^[0-9a-fA-F\s]+$", stripped):
        hex_clean = re.sub(r"\s", "", stripped)
        if len(hex_clean) >= 2 and len(hex_clean) % 2 == 0:
            suggestions.append(("base", 0.75, "Input looks like hexadecimal (Base16)"))

    # Check for Baconian (A/B groups or binary groups of 5)
    ab_clean = re.sub(r"[^ABab]", "", stripped)
    if len(ab_clean) >= 5 and len(ab_clean) % 5 == 0:
        if set(stripped.upper().replace(" ", "")) <= {"A", "B"}:
            suggestions.append(
                ("bacon", 0.9, "Input contains only A/B characters in groups of 5")
            )

    bin_clean = re.sub(r"[^01]", "", stripped)
    if len(bin_clean) >= 5 and len(bin_clean) % 5 == 0:
        if set(stripped.replace(" ", "")) <= {"0", "1"}:
            suggestions.append(
                ("bacon", 0.7, "Binary input in groups of 5 could be Baconian")
            )

    # For alphabetic text, analyze frequency characteristics
    cleaned = clean_text(text)
    if len(cleaned) >= 10:
        ioc = calculate_ioc(cleaned)

        # High IoC (~0.065+) suggests monoalphabetic cipher
        if ioc > 0.060:
            suggestions.append(
                (
                    "caesar",
                    0.7,
                    f"IoC={ioc:.4f} suggests monoalphabetic cipher (Caesar/Atbash/Affine)",
                )
            )
            suggestions.append(("atbash", 0.5, f"IoC={ioc:.4f} - could be Atbash"))
            suggestions.append(
                ("affine", 0.5, f"IoC={ioc:.4f} - could be Affine cipher")
            )
            suggestions.append(
                ("substitution", 0.4, f"IoC={ioc:.4f} - could be general substitution")
            )
        # Medium IoC suggests polyalphabetic
        elif ioc > 0.045:
            suggestions.append(
                (
                    "vigenere",
                    0.7,
                    f"IoC={ioc:.4f} suggests polyalphabetic cipher (Vigenere)",
                )
            )
            suggestions.append(("caesar", 0.3, f"IoC={ioc:.4f} - less likely Caesar"))
        # Low IoC suggests transposition or encoding
        else:
            suggestions.append(
                ("railfence", 0.5, f"IoC={ioc:.4f} - low IoC, could be transposition")
            )
            suggestions.append(
                ("vigenere", 0.4, f"IoC={ioc:.4f} - could be Vigenere with long key")
            )

        # Check for case-based Bacon if mixed case
        if any(c.isupper() for c in text if c.isalpha()) and any(
            c.islower() for c in text if c.isalpha()
        ):
            alpha = re.sub(r"[^a-zA-Z]", "", text)
            if len(alpha) % 5 == 0 or len(alpha) >= 25:
                suggestions.append(
                    (
                        "bacon",
                        0.3,
                        "Mixed-case alphabetic text could hide Baconian cipher",
                    )
                )

        # Rail fence is always worth trying for alphabetic text
        if (
            len(cleaned) >= 10
            and ("railfence", 0.5, f"IoC={ioc:.4f} - low IoC, could be transposition")
            not in suggestions
        ):
            suggestions.append(
                (
                    "railfence",
                    0.3,
                    "Alphabetic text - Rail Fence is always worth trying",
                )
            )

    # Sort by confidence (descending)
    suggestions.sort(key=lambda x: x[1], reverse=True)
    return suggestions


# ─── Main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="CTF Classical Cipher Solver Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{C.CYAN}Supported ciphers:{C.RESET}
  caesar        Caesar shift (brute-force all 25 shifts)
  rot13         ROT13 (Caesar shift of 13)
  rot47         ROT47 (printable ASCII rotation)
  atbash        Atbash mirror cipher
  affine        Affine cipher (brute-force all valid a,b pairs)
  vigenere      Vigenère cipher (auto key-length detection)
  railfence     Rail Fence transposition cipher
  substitution  Frequency-analysis substitution solver
  morse         Morse code decoder
  base          Base encoding detection (16/32/64/85)
  bacon         Baconian cipher decoder
  detect        Auto-detect cipher type
  all           Try all classical ciphers
""",
    )

    parser.add_argument("input", help="Text to decrypt or @filename")

    subparsers = parser.add_subparsers(dest="cipher", required=True)

    subparsers.add_parser("caesar", help="Solve Caesar shift automatically")
    subparsers.add_parser("rot13", help="Decode ROT13")
    subparsers.add_parser("rot47", help="Decode ROT47 (printable ASCII)")
    subparsers.add_parser("atbash", help="Solve Atbash cipher")
    subparsers.add_parser("affine", help="Solve Affine cipher (brute-force)")

    p_vig = subparsers.add_parser(
        "vigenere", help="Solve Vigenère cipher automatically"
    )
    p_vig.add_argument("-k", "--key", help="Use a specific key (skips auto-solve)")

    subparsers.add_parser("railfence", help="Solve Rail Fence transposition cipher")
    subparsers.add_parser("substitution", help="Frequency-analysis substitution solver")
    subparsers.add_parser("morse", help="Decode Morse code")
    subparsers.add_parser("base", help="Detect and decode base encodings")
    subparsers.add_parser("bacon", help="Decode Baconian cipher")
    subparsers.add_parser("detect", help="Auto-detect cipher type and solve")
    subparsers.add_parser("all", help="Try all classical ciphers")

    args = parser.parse_args()

    # Load input
    try:
        if args.input.startswith("@"):
            with open(args.input[1:], "r", encoding="utf-8") as f:
                text = f.read().strip()
        else:
            text = args.input
    except Exception as e:
        print(f"{C.RED}Error loading input: {e}{C.RESET}")
        sys.exit(1)

    print(
        f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  Classical Cipher Solver\n{'─' * 60}{C.RESET}"
    )
    print(f"  Input size: {len(text)} characters\n")

    # ── Display functions ────────────────────────────────────────────────

    def show_result(label, ptext, extra=""):
        """Display a single result with flag detection."""
        ex = excerpt_text(ptext)
        highlight = C.RED if check_flag(ptext) else C.GREEN
        flag_marker = (
            f"\n      {C.RED}{C.BOLD}⚑ FLAG DETECTED!{C.RESET}"
            if check_flag(ptext)
            else ""
        )
        extra_str = f" {C.DIM}{extra}{C.RESET}" if extra else ""
        print(f"  {label}{extra_str} | {highlight}{ex}{C.RESET}{flag_marker}")

    def run_caesar():
        print(f"  {C.YELLOW}⟳ Testing Caesar Cipher...{C.RESET}")
        results = solve_caesar(text)
        print(f"  {C.BOLD}Top 3 Caesar Shifts:{C.RESET}")
        for i, (score, shift, ptext) in enumerate(results[:3]):
            show_result(f"  [{i + 1}] {C.CYAN}Shift: {shift:2d}{C.RESET}", ptext)
        print()

    def run_rot13():
        print(f"  {C.YELLOW}⟳ Testing ROT13...{C.RESET}")
        ptext = solve_rot13(text)
        show_result(f"  {C.CYAN}ROT13{C.RESET}", ptext)
        print()

    def run_rot47():
        print(f"  {C.YELLOW}⟳ Testing ROT47...{C.RESET}")
        ptext = solve_rot47(text)
        show_result(f"  {C.CYAN}ROT47{C.RESET}", ptext)
        print()

    def run_atbash():
        print(f"  {C.YELLOW}⟳ Testing Atbash Cipher...{C.RESET}")
        ptext = solve_atbash(text)
        show_result(f"  {C.CYAN}Atbash{C.RESET}", ptext)
        print()

    def run_affine():
        print(f"  {C.YELLOW}⟳ Testing Affine Cipher (312 key pairs)...{C.RESET}")
        results = solve_affine(text)
        print(f"  {C.BOLD}Top 3 Affine Keys:{C.RESET}")
        for i, (score, a, b, ptext) in enumerate(results[:3]):
            show_result(f"  [{i + 1}] {C.CYAN}a={a:2d}, b={b:2d}{C.RESET}", ptext)
        print()

    def run_vigenere():
        print(f"  {C.YELLOW}⟳ Testing Vigenère Cipher...{C.RESET}")
        if hasattr(args, "key") and args.key:
            ptext = decrypt_vigenere(text, args.key)
            show_result(f"  {C.CYAN}Key: {args.key}{C.RESET}", ptext)
        else:
            results = solve_vigenere(text)
            if not results:
                print(f"  {C.RED}✗ Failed to find a valid Vigenère key.{C.RESET}")
                return

            print(f"  {C.BOLD}Top Vigenère Guesses:{C.RESET}")
            for i, (score, length, key, ptext) in enumerate(results):
                show_result(
                    f"  [{i + 1}] {C.CYAN}Key: {key:<10} (len: {length}){C.RESET}",
                    ptext,
                )
        print()

    def run_railfence():
        print(f"  {C.YELLOW}⟳ Testing Rail Fence Cipher...{C.RESET}")
        results = solve_railfence(text)
        if not results:
            print(f"  {C.RED}✗ Input too short for Rail Fence analysis.{C.RESET}")
            return
        print(f"  {C.BOLD}Top 3 Rail Counts:{C.RESET}")
        for i, (score, rails, ptext) in enumerate(results[:3]):
            show_result(f"  [{i + 1}] {C.CYAN}Rails: {rails:2d}{C.RESET}", ptext)
        print()

    def run_substitution():
        print(
            f"  {C.YELLOW}⟳ Testing Substitution Cipher (frequency analysis)...{C.RESET}"
        )
        mapping, freq_order, ptext = solve_substitution(text)
        if mapping is None:
            print(f"  {C.RED}✗ No alphabetic content to analyze.{C.RESET}")
            return

        show_result(f"  {C.CYAN}Frequency-mapped{C.RESET}", ptext)
        # Show the mapping table
        print(f"\n  {C.DIM}Mapping (cipher → plain):{C.RESET}")
        pairs = [f"{k}→{v}" for k, v in sorted(mapping.items())]
        # Display in rows of 13
        for i in range(0, len(pairs), 13):
            print(f"    {' '.join(pairs[i : i + 13])}")
        print()

    def run_morse():
        print(f"  {C.YELLOW}⟳ Testing Morse Code...{C.RESET}")
        ptext = solve_morse(text)
        if ptext.strip():
            show_result(f"  {C.CYAN}Morse{C.RESET}", ptext)
        else:
            print(f"  {C.RED}✗ Could not decode as Morse code.{C.RESET}")
        print()

    def run_base():
        print(f"  {C.YELLOW}⟳ Testing Base Encodings...{C.RESET}")
        results = solve_base_encodings(text)
        if not results:
            print(f"  {C.RED}✗ No valid base encoding detected.{C.RESET}")
        else:
            for encoding, decoded in results:
                show_result(f"  {C.CYAN}{encoding}{C.RESET}", decoded)
        print()

    def run_bacon():
        print(f"  {C.YELLOW}⟳ Testing Baconian Cipher...{C.RESET}")
        results = solve_bacon(text)
        if not results:
            print(f"  {C.RED}✗ Could not decode as Baconian cipher.{C.RESET}")
        else:
            for label, decoded in results:
                show_result(f"  {C.CYAN}{label}{C.RESET}", decoded)
        print()

    def run_detect():
        print(f"  {C.YELLOW}⟳ Analyzing input to detect cipher type...{C.RESET}")
        suggestions = detect_cipher(text)
        if not suggestions:
            print(
                f"  {C.RED}✗ Could not determine cipher type. Try 'all' mode.{C.RESET}"
            )
            return

        print(f"  {C.BOLD}Detected cipher types (by confidence):{C.RESET}")
        for cipher_name, confidence, reason in suggestions[:5]:
            bar = "█" * int(confidence * 20) + "░" * (20 - int(confidence * 20))
            print(
                f"  {C.CYAN}{cipher_name:<15}{C.RESET} [{bar}] {confidence:.0%}  {C.DIM}{reason}{C.RESET}"
            )
        print()

        # Run the top 2 suggestions
        print(f"  {C.BOLD}Running top suggestions...{C.RESET}\n")
        run_map = {
            "caesar": run_caesar,
            "rot13": run_rot13,
            "rot47": run_rot47,
            "atbash": run_atbash,
            "affine": run_affine,
            "vigenere": run_vigenere,
            "railfence": run_railfence,
            "substitution": run_substitution,
            "morse": run_morse,
            "base": run_base,
            "bacon": run_bacon,
        }
        seen = set()
        for cipher_name, _, _ in suggestions[:3]:
            if cipher_name not in seen and cipher_name in run_map:
                seen.add(cipher_name)
                run_map[cipher_name]()

    def run_all():
        """Run all cipher solvers."""
        run_caesar()
        run_rot13()
        run_rot47()
        run_atbash()
        run_affine()
        run_vigenere()
        run_railfence()
        run_substitution()
        run_morse()
        run_base()
        run_bacon()

    # ── Dispatch ─────────────────────────────────────────────────────────

    dispatch = {
        "caesar": run_caesar,
        "rot13": run_rot13,
        "rot47": run_rot47,
        "atbash": run_atbash,
        "affine": run_affine,
        "vigenere": run_vigenere,
        "railfence": run_railfence,
        "substitution": run_substitution,
        "morse": run_morse,
        "base": run_base,
        "bacon": run_bacon,
        "detect": run_detect,
        "all": run_all,
    }

    handler = dispatch.get(args.cipher)
    if handler:
        handler()
    else:
        print(f"{C.RED}Unknown cipher: {args.cipher}{C.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()

# 🔓 CTF Password Brute Force Toolkit

Scripts for password cracking and brute forcing in CTF challenges.

## Scripts

| Script | Description |
|--------|-------------|
| `hash_cracker.py` | Crack MD5/SHA1/SHA256/SHA512 hashes via wordlist or brute force, with mutation rules |
| `archive_cracker.py` | Brute force password-protected ZIP and PDF files |
| `wordlist_gen.py` | Generate custom wordlists from patterns, mutations, or charsets |
| `jwt_cracker.py` | Decode JWTs, brute force HMAC secrets, forge tokens with modified payloads |

## Requirements

```bash
python3 --version  # 3.7+

# Optional for PDF cracking:
pip install pikepdf
```

## Quick Reference

### Hash Cracker
```bash
# Wordlist attack
python3 hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt

# Wordlist with mutation rules (leet speak, suffixes, case)
python3 hash_cracker.py <hash> -w words.txt --rules

# Brute force (digits only, max 6 chars)
python3 hash_cracker.py <hash> --brute --charset digits --max-length 6

# Crack multiple hashes from file
python3 hash_cracker.py --hash-file hashes.txt -w rockyou.txt
```

### ZIP/PDF Cracker
```bash
# ZIP with wordlist
python3 archive_cracker.py secret.zip -w rockyou.txt

# ZIP brute force (4-digit PIN)
python3 archive_cracker.py locked.zip --brute --charset digits --max-length 4

# PDF with wordlist (requires pikepdf)
python3 archive_cracker.py encrypted.pdf -w passwords.txt
```

### Wordlist Generator
```bash
# Mutate base words (leet, case, suffixes)
python3 wordlist_gen.py --base-words admin,password,flag --rules full -o wordlist.txt

# Generate from pattern (# = digit, ? = lowercase, ^ = uppercase)
python3 wordlist_gen.py --pattern 'flag{####}' -o flags.txt
python3 wordlist_gen.py --pattern 'CTF{??##}' -o combos.txt

# All 4-digit PINs
python3 wordlist_gen.py --charset digits --min-length 4 --max-length 4 -o pins.txt

# Combine words with suffixes
python3 wordlist_gen.py --combine words.txt --with-suffixes '1,123,!' -o combined.txt
```

### JWT Cracker
```bash
# Decode a JWT
python3 jwt_cracker.py decode eyJhbGciOiJIUzI1NiJ9...

# Crack HMAC secret
python3 jwt_cracker.py crack eyJ... -w rockyou.txt
python3 jwt_cracker.py crack eyJ... --brute --charset lower --max-length 5

# Forge token with admin privileges
python3 jwt_cracker.py forge eyJ... --secret s3cret --payload '{"admin": true}'

# 'none' algorithm attack
python3 jwt_cracker.py forge eyJ... --secret x --algorithm none
```

## Typical CTF Workflow

```bash
# Found a hash? Crack it.
python3 hash_cracker.py <hash> -w rockyou.txt --rules

# Password-protected ZIP? Brute force it.
python3 archive_cracker.py challenge.zip --brute --charset digits -m 6

# Need a custom wordlist? Generate one.
python3 wordlist_gen.py --base-words company,ctf,admin --rules full -o custom.txt

# JWT web challenge? Decode → Crack → Forge.
python3 jwt_cracker.py decode <token>
python3 jwt_cracker.py crack <token> -w custom.txt
python3 jwt_cracker.py forge <token> --secret found_key --payload '{"role":"admin"}'
```

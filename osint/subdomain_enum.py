#!/usr/bin/env python3
"""
subdomain_enum.py - CTF Fast Subdomain Enumerator

Concurrently resolves subdomains against a target domain
using a built-in common wordlist or an external one.
"""

import argparse
import sys
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try to import dnspython, not strictly required but much better for CNAMEs
try:
    import dns.name
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

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

# Default top 100 subdomains for quick scans
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
    "ns3", "mail2", "new", "mysql", "old", "icpsignup", "testing", "ipv6",
    "staging", "secure", "api", "support", "s1", "app", "stats", "ns4",
    "portal", "beta", "exchange", "shop", "login", "server", "demo", "cloud",
    "s2", "host", "video", "download", "auth", "images", "proxy", "server1",
    "backup", "store", "chat", "mx", "gateway", "remote", "status", "web",
    "cdn", "files", "1", "dashboard", "billing", "vpn1", "corp", "web1",
    "git", "git", "jenkins", "jira", "gitlab", "grafana", "prometheus",
    "db", "intranet", "help", "assets", "mobile", "owa", "monitor", "vps"
]


def resolve_subdomain(subdomain, domain, resolver=None):
    """Attempt to resolve a single subdomain."""
    target = f"{subdomain}.{domain}"
    
    try:
        # If we have dnspython installed, we can get much better data
        if HAS_DNS and resolver:
            try:
                # Get A records
                answers = resolver.resolve(target, 'A', lifetime=2)
                ips = [rdata.address for rdata in answers]
                
                # Check for CNAME
                cname = ""
                try:
                    cname_ans = resolver.resolve(target, 'CNAME', lifetime=2)
                    cname = str(cname_ans[0].target)
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    pass
                    
                return True, target, ips, cname
            
            except dns.resolver.NXDOMAIN:
                return False, target, [], ""
            except Exception:
                # Timeout or servfail, try fallback
                pass
                
        # Fallback to standard socket resolution
        ip = socket.gethostbyname(target)
        return True, target, [ip], ""
        
    except socket.gaierror:
        # Name or service not known
        return False, target, [], ""
    except Exception:
        return False, target, [], ""


def check_wildcard(domain, resolver=None):
    """Check if the domain has a wildcard DNS record."""
    random_sub = "fsdfj2934sdnlk34j2"
    is_valid, target, ips, _ = resolve_subdomain(random_sub, domain, resolver)
    if is_valid:
        return True, ips
    return False, []


def main():
    parser = argparse.ArgumentParser(
        description='CTF Fast Subdomain Enumerator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s target.htb -w subdomains.txt -t 50
""")

    parser.add_argument('domain', help='Target domain (e.g., example.com)')
    parser.add_argument('-w', '--wordlist', help='Path to custom wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=30, help='Number of concurrent threads (default: 30)')
    parser.add_argument('-o', '--output', help='Save discovered subdomains to text file')
    
    args = parser.parse_args()
    domain = args.domain.strip()
    
    # Strip any http:// or trailing slashes
    if "://" in domain:
        domain = domain.split("://")[1]
    domain = domain.split("/")[0]

    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  Subdomain Enumerator\n{'─' * 60}{C.RESET}")
    print(f"  {C.BOLD}Target:{C.RESET}  {domain}")
    
    
    # Setup wordlist
    wordlist = []
    if args.wordlist:
        try:
            with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"  {C.BOLD}Words:{C.RESET}   {len(wordlist):,} (custom)")
        except Exception as e:
            print(f"  {C.RED}Error loading wordlist: {e}{C.RESET}")
            sys.exit(1)
    else:
        wordlist = DEFAULT_WORDLIST
        print(f"  {C.BOLD}Words:{C.RESET}   {len(wordlist)} (default quick list)")

    if not HAS_DNS:
        print(f"  {C.YELLOW}[!] 'dnspython' not installed. CNAME detection disabled.{C.RESET}")
        print(f"  {C.DIM}To enable: pip install dnspython{C.RESET}")
        resolver = None
    else:
        # Configure the resolver using fast public DNS
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        resolver.timeout = 2
        resolver.lifetime = 2

    # Check for wildcards
    print(f"\n  {C.DIM}Checking for wildcard DNS...{C.RESET}")
    is_wildcard, wc_ips = check_wildcard(domain, resolver)
    if is_wildcard:
        print(f"  {C.RED}[!] Warning: Wildcard DNS detected!{C.RESET}")
        print(f"  {C.DIM}Requests matching {wc_ips} will be ignoring as false positives.{C.RESET}\n")
    else:
        print(f"  {C.GREEN}No wildcard DNS detected. Clean results expected.{C.RESET}\n")

    print(f"  {C.YELLOW}⟳ Resolving subdomains ({args.threads} threads)...{C.RESET}\n")

    found_count = 0
    results = []

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(resolve_subdomain, sub, domain, resolver): sub 
                for sub in wordlist
            }
            
            for future in as_completed(futures):
                is_valid, target, ips, cname = future.result()
                
                if is_valid:
                    # Filter out wildcard matches
                    if is_wildcard and any(ip in wc_ips for ip in ips):
                        continue
                        
                    found_count += 1
                    ip_str = ", ".join(ips)
                    
                    if cname:
                        print(f"  {C.GREEN}▶ {target:<25}{C.RESET} : {ip_str:<15} {C.MAGENTA}(CNAME: {cname}){C.RESET}")
                        results.append((target, ip_str, cname))
                    else:
                        print(f"  {C.GREEN}▶ {target:<25}{C.RESET} : {ip_str}")
                        results.append((target, ip_str, ""))
                        
    except KeyboardInterrupt:
        print(f"\n  {C.YELLOW}Scan aborted by user.{C.RESET}")

    print(f"\n{C.CYAN}{'─' * 60}{C.RESET}")
    print(f"  {C.BOLD}Scan Complete.{C.RESET}")
    print(f"  {C.GREEN}Found {found_count} valid subdomains.{C.RESET}")
    
    if found_count > 0 and args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(f"Subdomains for {domain}\n")
                f.write("="*40 + "\n")
                for target, ips, cname in sorted(results):
                    line = f"{target} [{ips}]"
                    if cname: line += f" CNAME: {cname}"
                    f.write(line + "\n")
            print(f"  {C.GREEN}Results saved to: {args.output}{C.RESET}")
        except Exception as e:
            print(f"  {C.RED}Failed to write to file: {e}{C.RESET}")
            
    print()


if __name__ == '__main__':
    main()

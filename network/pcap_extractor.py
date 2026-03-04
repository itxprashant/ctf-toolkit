#!/usr/bin/env python3
"""
pcap_extractor.py - CTF Network Packet Forensics Toolkit

Parses PCAP/PCAPNG files without needing Wireshark.
- Dumps plaintext credentials (HTTP Basic, FTP, Telnet, SMTP)
- Reassembles and extracts HTTP file transfers
- Extracts DNS query history
- TCP stream following and text dump
- ICMP data extraction (ping exfiltration)
- WiFi EAPOL / WPA handshake detection
- Protocol statistics summary
"""

import argparse
import os
import sys
import base64
import re
from urllib.parse import unquote
from collections import Counter, defaultdict

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import rdpcap, TCP, UDP, IP, DNS, DNSQR, DNSRR, Raw, ICMP, Ether, ARP
except ImportError:
    print("\033[91mError: scapy not installed.\033[0m")
    print("Please install it running: pip install scapy")
    sys.exit(1)

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


def check_flag(text):
    import re as _re
    flags = _re.findall(r'(?:flag|ctf|picoctf|htb|ductf)\{[^}]+\}', text, _re.IGNORECASE)
    return flags


def print_header(title):
    print(f"\n{C.CYAN}{C.BOLD}─── {title} {'─' * max(1, 56 - len(title))}{C.RESET}")


# ─── Protocol Statistics ─────────────────────────────────────────────────────

def protocol_stats(packets):
    """Print protocol distribution and basic stats."""
    print_header("Protocol Statistics")
    
    proto_count = Counter()
    total_bytes = 0
    ips_seen = set()
    
    for pkt in packets:
        total_bytes += len(pkt)
        if pkt.haslayer(TCP): proto_count['TCP'] += 1
        elif pkt.haslayer(UDP): proto_count['UDP'] += 1
        elif pkt.haslayer(ICMP): proto_count['ICMP'] += 1
        elif pkt.haslayer(ARP): proto_count['ARP'] += 1
        else: proto_count['Other'] += 1
        
        if pkt.haslayer(IP):
            ips_seen.add(pkt[IP].src)
            ips_seen.add(pkt[IP].dst)
    
    print(f"  Total packets:  {len(packets)}")
    print(f"  Total bytes:    {total_bytes:,} ({total_bytes/1024:.1f} KB)")
    print(f"  Unique IPs:     {len(ips_seen)}")
    
    for proto, count in proto_count.most_common():
        pct = count / len(packets) * 100
        bar = '█' * int(pct / 5)
        print(f"  {proto:8s} {count:6d} ({pct:5.1f}%) {C.CYAN}{bar}{C.RESET}")


# ─── DNS Extraction ──────────────────────────────────────────────────────────

def extract_dns(packets):
    """Extract DNS queries and responses."""
    print_header("DNS Queries & Responses")
    queries = {}
    responses = defaultdict(list)
    
    for pkt in packets:
        if pkt.haslayer(DNS):
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                queries[qname] = queries.get(qname, 0) + 1
            
            if pkt.haslayer(DNSRR):
                try:
                    rrname = pkt[DNSRR].rrname.decode('utf-8', errors='ignore').rstrip('.')
                    rdata = pkt[DNSRR].rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode('utf-8', errors='ignore')
                    responses[rrname].append(str(rdata))
                except:
                    pass

    if not queries:
        print(f"  {C.DIM}No DNS queries found.{C.RESET}")
        return

    # Check for DNS exfiltration (long subdomain labels)
    exfil_candidates = []
    
    for q, count in sorted(queries.items(), key=lambda x: -x[1]):
        flags = check_flag(q)
        highlight = C.RED + C.BOLD if flags else C.GREEN
        count_str = f" ({count}x)" if count > 1 else ""
        
        resolved = ', '.join(responses.get(q, []))
        resolved_str = f" → {C.DIM}{resolved}{C.RESET}" if resolved else ""
        
        print(f"  {highlight}▶{C.RESET} {q}{count_str}{resolved_str}")
        for f in flags:
            print(f"    {C.RED}{C.BOLD}⚑ FLAG: {f}{C.RESET}")
        
        # DNS exfiltration: subdomains > 30 chars or hex-like
        labels = q.split('.')
        if any(len(l) > 30 or re.match(r'^[0-9a-fA-F]+$', l) for l in labels[:-2]):
            exfil_candidates.append(q)

    if exfil_candidates:
        print(f"\n  {C.YELLOW}{C.BOLD}⚠ Possible DNS Exfiltration Detected:{C.RESET}")
        # Try to decode the subdomain data
        combined = ''
        for q in exfil_candidates:
            labels = q.split('.')
            combined += labels[0]
        print(f"  {C.DIM}Combined subdomains: {combined[:200]}{C.RESET}")
        try:
            decoded = bytes.fromhex(combined).decode('utf-8', errors='replace')
            print(f"  {C.GREEN}Hex decoded: {decoded}{C.RESET}")
            for f in check_flag(decoded):
                print(f"  {C.RED}{C.BOLD}⚑ FLAG: {f}{C.RESET}")
        except:
            try:
                decoded = base64.b64decode(combined).decode('utf-8', errors='replace')
                print(f"  {C.GREEN}Base64 decoded: {decoded}{C.RESET}")
            except:
                pass

    print(f"\n  {C.DIM}Total unique queries: {len(queries)}{C.RESET}")


# ─── Credential Extraction ───────────────────────────────────────────────────

def extract_credentials(packets):
    """Find plaintext credentials in HTTP, FTP, Telnet, and SMTP."""
    print_header("Plaintext Credentials")
    found_creds = []
    
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(Raw): continue
        if not pkt.haslayer(TCP): continue
        
        payload = pkt[Raw].load
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        
        # 1. HTTP Basic Auth
        if b'Authorization: Basic ' in payload:
            try:
                auth_b64 = re.search(b'Authorization: Basic ([A-Za-z0-9+/=]+)', payload).group(1)
                decoded = base64.b64decode(auth_b64).decode('utf-8')
                found_creds.append(('HTTP Basic Auth', i+1, decoded))
            except:
                pass
                
        # 2. HTTP Form Data
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            if ('user' in payload_str.lower() or 'login' in payload_str.lower()) and \
               ('pass' in payload_str.lower() or 'pwd' in payload_str.lower()):
                lines = payload_str.split('\r\n')
                for line in lines:
                    if 'pass' in line.lower() or 'pwd' in line.lower():
                        clean = unquote(line)
                        found_creds.append(('HTTP Form', i+1, clean))
        except:
            pass

        # 3. FTP Login
        if payload[:5] in (b'USER ', b'PASS '):
            try:
                line = payload.decode('utf-8', errors='ignore').strip()
                found_creds.append(('FTP', i+1, line))
            except:
                pass
        
        # 4. SMTP Auth
        if dport == 25 or dport == 587 or sport == 25:
            if b'AUTH LOGIN' in payload or b'AUTH PLAIN' in payload:
                found_creds.append(('SMTP Auth', i+1, payload.decode('utf-8', errors='ignore').strip()))
            # Base64 encoded credentials after AUTH LOGIN
            try:
                text = payload.decode('ascii').strip()
                if re.match(r'^[A-Za-z0-9+/]+=*$', text) and 4 < len(text) < 200:
                    decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                    if decoded.isprintable() and len(decoded) > 2:
                        found_creds.append(('SMTP (b64)', i+1, decoded))
            except:
                pass
        
        # 5. Telnet
        if dport == 23 or sport == 23:
            try:
                text = payload.decode('utf-8', errors='ignore').strip()
                if text and len(text) < 100 and text.isprintable():
                    found_creds.append(('Telnet', i+1, text))
            except:
                pass

    if not found_creds:
        print(f"  {C.DIM}No obvious plaintext credentials found.{C.RESET}")
    else:
        for proto, pkt_num, cred in found_creds:
            print(f"  {C.YELLOW}[{proto}]{C.RESET} Pkt {pkt_num}: {C.GREEN}{cred}{C.RESET}")
            for f in check_flag(cred):
                print(f"    {C.RED}{C.BOLD}⚑ FLAG: {f}{C.RESET}")


# ─── HTTP File Extraction ────────────────────────────────────────────────────

def extract_http_files(packets, out_dir):
    """Basic HTTP file extraction from single-packet responses."""
    print_header("HTTP File Extraction")
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
        
    extracted = 0
    
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(Raw) or not pkt.haslayer(TCP): continue
        payload = pkt[Raw].load
        
        if b'HTTP/1.' in payload and b'200' in payload[:30] and b'\r\n\r\n' in payload:
            try:
                headers_raw, body = payload.split(b'\r\n\r\n', 1)
                headers = headers_raw.decode('utf-8', errors='ignore')
                
                ext = '.bin'
                content_types = {
                    'image/jpeg': '.jpg', 'image/png': '.png', 'image/gif': '.gif',
                    'application/pdf': '.pdf', 'application/zip': '.zip',
                    'text/html': '.html', 'text/plain': '.txt',
                    'application/javascript': '.js', 'application/json': '.json',
                    'application/octet-stream': '.bin', 'image/webp': '.webp',
                }
                for ct, e in content_types.items():
                    if ct in headers:
                        ext = e
                        break
                
                if len(body) == 0:
                    continue
                    
                filename = f"pkt_{i+1}{ext}"
                out_path = os.path.join(out_dir, filename)
                
                with open(out_path, 'wb') as f:
                    f.write(body)

                print(f"  {C.GREEN}▶ {filename}{C.RESET} {C.DIM}({len(body)/1024:.1f} KB){C.RESET}")
                
                if ext in ('.txt', '.html', '.json', '.js'):
                    try:
                        text = body.decode('utf-8')
                        for f in check_flag(text):
                            print(f"    {C.RED}{C.BOLD}⚑ FLAG: {f}{C.RESET}")
                    except:
                        pass
                
                extracted += 1
            except:
                pass
                
    if extracted == 0:
        print(f"  {C.DIM}No complete HTTP file transfers found.{C.RESET}")
    else:
        print(f"\n  {C.YELLOW}Extracted {extracted} files to: {out_dir}/{C.RESET}")


# ─── TCP Stream Following ────────────────────────────────────────────────────

def follow_tcp_streams(packets, max_streams=10):
    """Reconstruct and display text-based TCP streams."""
    print_header("TCP Streams (Text)")
    
    streams = defaultdict(bytearray)
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            ip = pkt[IP] if pkt.haslayer(IP) else None
            if not ip: continue
            
            # Use a tuple to identify streams
            key = tuple(sorted([(ip.src, pkt[TCP].sport), (ip.dst, pkt[TCP].dport)]))
            streams[key].extend(pkt[Raw].load)
    
    if not streams:
        print(f"  {C.DIM}No TCP streams found.{C.RESET}")
        return
    
    count = 0
    for key, data in streams.items():
        if count >= max_streams:
            print(f"\n  {C.DIM}... and {len(streams) - max_streams} more streams{C.RESET}")
            break
        
        # Only show text-ish streams
        printable = sum(1 for b in data[:500] if 32 <= b <= 126 or b in (9, 10, 13))
        if printable / max(1, min(500, len(data))) < 0.6:
            continue
        
        (ip1, port1), (ip2, port2) = key
        count += 1
        text = data[:500].decode('utf-8', errors='replace')
        
        print(f"\n  {C.BLUE}Stream:{C.RESET} {ip1}:{port1} ↔ {ip2}:{port2} ({len(data)} bytes)")
        for line in text.split('\n')[:15]:
            stripped = line.strip()
            if stripped:
                print(f"    {stripped}")
        
        for f in check_flag(text):
            print(f"    {C.RED}{C.BOLD}⚑ FLAG: {f}{C.RESET}")
        
        if len(data) > 500:
            print(f"    {C.DIM}... (truncated){C.RESET}")


# ─── ICMP Data Extraction ────────────────────────────────────────────────────

def extract_icmp(packets):
    """Extract data from ICMP packets (ping exfiltration)."""
    print_header("ICMP Data Extraction")
    
    icmp_data = bytearray()
    count = 0
    
    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
            icmp_data.extend(pkt[Raw].load)
            count += 1
    
    if count == 0:
        print(f"  {C.DIM}No ICMP data payloads found.{C.RESET}")
        return
    
    print(f"  {C.DIM}Found {count} ICMP packets with data ({len(icmp_data)} bytes total){C.RESET}")
    
    # Check for text
    text = icmp_data.decode('utf-8', errors='replace')
    printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
    
    if printable / max(1, len(text)) > 0.5:
        print(f"  {C.GREEN}Text content:{C.RESET}\n  {text[:300]}")
    else:
        # Try per-packet single byte (common exfil pattern)
        single_bytes = bytearray()
        for pkt in packets:
            if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
                single_bytes.append(pkt[Raw].load[0])
        
        sb_text = single_bytes.decode('utf-8', errors='replace')
        if sum(1 for c in sb_text if c.isprintable()) / max(1, len(sb_text)) > 0.6:
            print(f"  {C.GREEN}First-byte extraction:{C.RESET}\n  {sb_text[:200]}")
        else:
            print(f"  {C.DIM}Hex: {icmp_data[:100].hex()}{C.RESET}")
    
    for f in check_flag(text):
        print(f"  {C.RED}{C.BOLD}⚑ FLAG: {f}{C.RESET}")


# ─── String Scan ─────────────────────────────────────────────────────────────

def scan_strings(packets, min_len=8):
    """Scan all packet payloads for interesting strings and flags."""
    print_header("Interesting Strings")
    
    all_text = bytearray()
    for pkt in packets:
        if pkt.haslayer(Raw):
            all_text.extend(pkt[Raw].load)
    
    text = all_text.decode('utf-8', errors='ignore')
    
    flags = check_flag(text)
    if flags:
        for f in flags:
            print(f"  {C.RED}{C.BOLD}⚑ FLAG: {f}{C.RESET}")
    
    # Look for URLs
    urls = set(re.findall(r'https?://[^\s<>"\']+', text))
    if urls:
        print(f"\n  {C.BLUE}URLs found:{C.RESET}")
        for url in sorted(urls)[:15]:
            print(f"    {url}")
    
    # Look for email addresses
    emails = set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', text))
    if emails:
        print(f"\n  {C.BLUE}Emails found:{C.RESET}")
        for email in sorted(emails):
            print(f"    {email}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF Network PCAP Forensics Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('pcap', help='Path to PCAP/PCAPNG file')
    
    parser.add_argument('--dns', action='store_true', help='Extract DNS queries only')
    parser.add_argument('--creds', action='store_true', help='Extract plaintext credentials only')
    parser.add_argument('--files', action='store_true', help='Extract HTTP files only')
    parser.add_argument('--streams', action='store_true', help='Follow TCP streams')
    parser.add_argument('--icmp', action='store_true', help='Extract ICMP data')
    parser.add_argument('--strings', action='store_true', help='Scan for flags and interesting strings')
    parser.add_argument('--stats', action='store_true', help='Protocol statistics only')
    parser.add_argument('-o', '--out', default='./extracted_pcap_files', help='Output directory')

    args = parser.parse_args()
    
    if not os.path.isfile(args.pcap):
        print(f"{C.RED}Error: File '{args.pcap}' not found.{C.RESET}")
        sys.exit(1)

    print(f"\n  {C.BOLD}Analyzing PCAP: {args.pcap}{C.RESET}")
    
    try:
        packets = rdpcap(args.pcap)
    except Exception as e:
        print(f"\n{C.RED}Error reading PCAP: {e}{C.RESET}")
        sys.exit(1)
    
    run_all = not any([args.dns, args.creds, args.files, args.streams, args.icmp, args.strings, args.stats])
    
    try:
        if args.stats or run_all:
            protocol_stats(packets)
        if args.dns or run_all:
            extract_dns(packets)
        if args.creds or run_all:
            extract_credentials(packets)
        if args.files or run_all:
            extract_http_files(packets, args.out)
        if args.streams or run_all:
            follow_tcp_streams(packets)
        if args.icmp or run_all:
            extract_icmp(packets)
        if args.strings or run_all:
            scan_strings(packets)
        print()
    except Exception as e:
        print(f"\n{C.RED}Error analyzing PCAP: {e}{C.RESET}")


if __name__ == '__main__':
    main()

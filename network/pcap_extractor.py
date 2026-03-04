#!/usr/bin/env python3
"""
pcap_extractor.py - CTF Network Packet Forensics Toolkit

Parses PCAP/PCAPNG files without needing Wireshark.
- Dumps plaintext credentials (HTTP Basic, FTP, Telnet)
- Reassembles and extracts HTTP file transfers
- Extracts DNS query history
"""

import argparse
import os
import sys
import base64
import re
from urllib.parse import unquote

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import rdpcap, TCP, UDP, IP, DNS, DNSQR, Raw
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
    if 'flag{' in text.lower() or 'ctf{' in text.lower():
        return f"{C.RED}{C.BOLD}⚑ FLAG FOUND: {text}{C.RESET}"
    return text


def extract_dns(pcap_file):
    """Extract all DNS queries from the PCAP."""
    print(f"\n{C.CYAN}{C.BOLD}─── DNS Queries ───────────────────────────────────────────────{C.RESET}")
    packets = rdpcap(pcap_file)
    queries = set()
    
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            queries.add(qname)
            
    if not queries:
        print(f"  {C.DIM}No DNS queries found.{C.RESET}")
        return
        
    for q in sorted(queries):
        highlight = check_flag(q)
        print(f"  {C.GREEN}▶{C.RESET} {highlight}")
    print(f"\n  {C.DIM}Total unique queries: {len(queries)}{C.RESET}")


def extract_credentials(pcap_file):
    """Find plaintext credentials in HTTP, FTP, and Telnet traffic."""
    print(f"\n{C.CYAN}{C.BOLD}─── Plaintext Credentials ─────────────────────────────────────{C.RESET}")
    packets = rdpcap(pcap_file)
    found_creds = False
    
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(Raw): continue
        if not pkt.haslayer(TCP): continue
        
        payload = pkt[Raw].load
        
        # 1. HTTP Basic Auth
        if b'Authorization: Basic ' in payload:
            try:
                auth_b64 = re.search(b'Authorization: Basic ([A-Za-z0-9+/=]+)', payload).group(1)
                decoded = base64.b64decode(auth_b64).decode('utf-8')
                print(f"  {C.YELLOW}[HTTP Basic Auth]{C.RESET} Packet {i+1}: {C.GREEN}{decoded}{C.RESET}")
                found_creds = True
            except:
                pass
                
        # 2. HTTP Form Data / GET Params (Basic heuristic)
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            if ('user=' in payload_str or 'username=' in payload_str or 'login=' in payload_str) and \
               ('pass=' in payload_str or 'password=' in payload_str or 'pwd=' in payload_str):
                
                # Try to extract the whole line or POST body
                lines = payload_str.split('\r\n')
                for line in lines:
                    if 'pass=' in line or 'password=' in line:
                        clean = unquote(line)
                        print(f"  {C.YELLOW}[HTTP Form/GET]{C.RESET} Packet {i+1}: {C.GREEN}{clean}{C.RESET}")
                        found_creds = True
        except:
            pass

        # 3. FTP Login
        if b'USER ' in payload[:5] or b'PASS ' in payload[:5]:
            try:
                line = payload.decode('utf-8', errors='ignore').strip()
                print(f"  {C.YELLOW}[FTP]{C.RESET} Packet {i+1}: {C.GREEN}{line}{C.RESET}")
                found_creds = True
            except:
                pass
                
    if not found_creds:
        print(f"  {C.DIM}No obvious plaintext credentials found.{C.RESET}")


def extract_http_files(pcap_file, out_dir):
    """Extremely simplified HTTP file carving."""
    print(f"\n{C.CYAN}{C.BOLD}─── HTTP File Extraction ──────────────────────────────────────{C.RESET}")
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
        
    packets = rdpcap(pcap_file)
    extracted = 0
    
    # TCP stream reassembly is highly complex.
    # We do a naive approach: look for 'HTTP/1.1 200 OK' and extract whatever follows '\r\n\r\n'
    # For a real robust approach we'd trace SYN-ACK and sequence numbers, 
    # but naive works for 90% of basic CTF PCAPs.
    
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(Raw): continue
        if not pkt.haslayer(TCP): continue
        
        payload = pkt[Raw].load
        
        if b'HTTP/1.1 200 OK' in payload and b'\r\n\r\n' in payload:
            try:
                headers_raw, body = payload.split(b'\r\n\r\n', 1)
                headers = headers_raw.decode('utf-8', errors='ignore')
                
                # Check for Content-Type
                ext = '.bin'
                if 'image/jpeg' in headers: ext = '.jpg'
                elif 'image/png' in headers: ext = '.png'
                elif 'application/pdf' in headers: ext = '.pdf'
                elif 'application/zip' in headers: ext = '.zip'
                elif 'text/html' in headers: ext = '.html'
                elif 'text/plain' in headers: ext = '.txt'
                
                if len(body) == 0:
                    continue # Fragmented body, naive approach fails here
                    
                filename = f"packet_{i+1}_extracted{ext}"
                out_path = os.path.join(out_dir, filename)
                
                with open(out_path, 'wb') as f:
                    f.write(body)
                    
                size_kb = len(body) / 1024
                print(f"  {C.GREEN}▶ Extracted:{C.RESET} {filename} {C.DIM}({size_kb:.1f} KB){C.RESET}")
                
                # Check for text flags
                if ext in ['.txt', '.html', '.bin']:
                    try:
                        text = body.decode('utf-8')
                        if 'flag{' in text.lower() or 'ctf{' in text.lower():
                            print(f"      {C.RED}{C.BOLD}⚑ FLAG FOUND IN FILE!{C.RESET}")
                    except:
                        pass
                
                extracted += 1
            except Exception as e:
                pass
                
    if extracted == 0:
        print(f"  {C.DIM}No complete HTTP file transfers found in single packets.{C.RESET}")
        print(f"  {C.DIM}(Note: Fragmented streams are not supported by this basic script){C.RESET}")
    else:
        print(f"\n  {C.YELLOW}Extracted files saved to: {out_dir}/{C.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='CTF Network PCAP Forensics Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('pcap', help='Path to PCAP/PCAPNG file')
    
    parser.add_argument('--dns', action='store_true', help='Extract DNS queries only')
    parser.add_argument('--creds', action='store_true', help='Extract plaintext credentials only')
    parser.add_argument('--files', action='store_true', help='Extract HTTP files only')
    parser.add_argument('-o', '--out', default='./extracted_pcap_files', help='Output directory for extracted files')

    args = parser.parse_args()
    
    if not os.path.isfile(args.pcap):
        print(f"{C.RED}Error: File '{args.pcap}' not found.{C.RESET}")
        sys.exit(1)

    print(f"\n  {C.BOLD}Analyzing PCAP: {args.pcap}{C.RESET}")
    print(f"  {C.DIM}This may take a moment for large files...{C.RESET}")
    
    run_all = not (args.dns or args.creds or args.files)
    
    try:
        if args.dns or run_all:
            extract_dns(args.pcap)
            
        if args.creds or run_all:
            extract_credentials(args.pcap)
            
        if args.files or run_all:
            extract_http_files(args.pcap, args.out)
            
        print()
    except Exception as e:
        print(f"\n{C.RED}Error analyzing PCAP: {e}{C.RESET}")


if __name__ == '__main__':
    main()

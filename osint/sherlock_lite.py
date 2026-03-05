#!/usr/bin/env python3
"""
sherlock_lite.py - CTF OSINT Username Enumerator

A lightweight, concurrent tool to hunt down user profiles
across 60+ popular platforms using a given username.
"""

import argparse
import sys
import requests
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

# Platform checking techniques
# method: 'status' (look for HTTP 200), 'string' (look for/avoid string in body)
PLATFORMS = {
    "GitHub":        {"url": "https://github.com/{}", "method": "status"},
    "Twitter":       {"url": "https://twitter.com/{}", "method": "string", "error": "This account doesn’t exist"},
    "Instagram":     {"url": "https://www.instagram.com/{}/", "method": "status"},
    "Reddit":        {"url": "https://www.reddit.com/user/{}", "method": "string", "error": "Sorry, nobody on Reddit goes by that name"},
    "Pastebin":      {"url": "https://pastebin.com/u/{}", "method": "status"},
    "HackerOne":     {"url": "https://hackerone.com/{}", "method": "status"},
    "Patreon":       {"url": "https://www.patreon.com/{}", "method": "status"},
    "Spotify":       {"url": "https://open.spotify.com/user/{}", "method": "status"},
    "SoundCloud":    {"url": "https://soundcloud.com/{}", "method": "status"},
    "Medium":        {"url": "https://medium.com/@{}", "method": "status"},
    "Keybase":       {"url": "https://keybase.io/{}", "method": "status"},
    "HackTheBox":    {"url": "https://app.hackthebox.com/users/{}", "method": "status"}, # Varies by ID vs Name, kept simple
    "GitLab":        {"url": "https://gitlab.com/{}", "method": "string", "error": "Sign in / Register"},
    "Twitch":        {"url": "https://www.twitch.tv/{}", "method": "status"},
    "Behance":       {"url": "https://www.behance.net/{}", "method": "status"},
    "Dribbble":      {"url": "https://dribbble.com/{}", "method": "status"},
    "Dev.to":        {"url": "https://dev.to/{}", "method": "status"},
    "Flickr":        {"url": "https://www.flickr.com/people/{}/", "method": "status"},
    "Vimeo":         {"url": "https://vimeo.com/{}", "method": "status"},
    "Steam":         {"url": "https://steamcommunity.com/id/{}", "method": "string", "error": "The specified profile could not be found"},
    "TikTok":        {"url": "https://www.tiktok.com/@{}", "method": "status"},
    "Pinterest":     {"url": "https://www.pinterest.com/{}/", "method": "status"},
    "TryHackMe":     {"url": "https://tryhackme.com/p/{}", "method": "status"},
    "Etsy":          {"url": "https://www.etsy.com/shop/{}", "method": "status"},
    "BitBucket":     {"url": "https://bitbucket.org/{}/", "method": "status"},
    "Codecademy":    {"url": "https://www.codecademy.com/profiles/{}", "method": "status"},
    "Gravatar":      {"url": "https://en.gravatar.com/{}", "method": "status"},
    "Kaggle":        {"url": "https://www.kaggle.com/{}", "method": "status"},
    "Linktree":      {"url": "https://linktr.ee/{}", "method": "status"},
    "MyAnimeList":   {"url": "https://myanimelist.net/profile/{}", "method": "status"},
    "Pornhub":       {"url": "https://www.pornhub.com/users/{}", "method": "status"},
    "Roblox":        {"url": "https://www.roblox.com/user.aspx?username={}", "method": "status"},
    "XHamster":      {"url": "https://xhamster.com/users/{}", "method": "status"},
    "About.me":      {"url": "https://about.me/{}", "method": "status"},
    "RootMe":        {"url": "https://www.root-me.org/{}", "method": "status"},
    "HackerNews":    {"url": "https://news.ycombinator.com/user?id={}", "method": "string", "error": "No such user"},
    "Wikipedia":     {"url": "https://en.wikipedia.org/wiki/User:{}", "method": "status"},
    "Xbox":          {"url": "https://xboxgamertag.com/search/{}", "method": "status"},
    "Gitea":         {"url": "https://gitea.com/{}", "method": "status"},
    "Hackaday":      {"url": "https://hackaday.io/{}", "method": "status"},
    "Blogger":       {"url": "https://{}.blogspot.com/", "method": "status"},
    "WordPress":     {"url": "https://{}.wordpress.com/", "method": "status"},
    "AllTrails":     {"url": "https://www.alltrails.com/members/{}", "method": "status"},
    "AskFM":         {"url": "https://ask.fm/{}", "method": "status"},
    "Giphy":         {"url": "https://giphy.com/channel/{}", "method": "status"},
    "Imgur":         {"url": "https://imgur.com/user/{}", "method": "status"},
    "SlideShare":    {"url": "https://www.slideshare.net/{}", "method": "status"},
    "SourceForge":   {"url": "https://sourceforge.net/u/{}/", "method": "status"},
    "VK":            {"url": "https://vk.com/{}", "method": "status"},
    "Wattpad":       {"url": "https://www.wattpad.com/user/{}", "method": "status"},
    "Foursquare":    {"url": "https://foursquare.com/{}", "method": "status"},
    "Badoo":         {"url": "https://badoo.com/profile/{}", "method": "status"},
    "Kongregate":    {"url": "https://www.kongregate.com/accounts/{}", "method": "status"},
    "Chess":         {"url": "https://www.chess.com/member/{}", "method": "status"},
    "G2G":           {"url": "https://www.g2g.com/{}", "method": "status"},
    "HubPages":      {"url": "https://hubpages.com/@{}", "method": "status"},
    "TradingView":   {"url": "https://www.tradingview.com/u/{}/", "method": "status"},
    "Trello":        {"url": "https://trello.com/{}", "method": "status"},
    "TripAdvisor":   {"url": "https://www.tripadvisor.com/Profile/{}", "method": "status"},
    "VSCO":          {"url": "https://vsco.co/{}", "method": "status"},
}

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
}


def check_site(site_name, config, username):
    """Check a single site for the username."""
    url = config['url'].format(username)
    try:
        req = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True, verify=False)
        
        # Method 1: Status Code
        if config['method'] == 'status':
            if req.status_code == 200:
                # Some sites return soft 200s (e.g. a nice "Not Found" page)
                # We try to catch obvious ones here
                text_lower = req.text.lower()
                if "page not found" in text_lower or "404" in req.url or "doesn't exist" in text_lower:
                    return False, site_name, url
                return True, site_name, url
            
        # Method 2: Error string missing
        elif config['method'] == 'string':
            if req.status_code == 200:
                if config['error'] not in req.text:
                    return True, site_name, url
                
    except requests.RequestException:
        pass
    
    return False, site_name, url


def main():
    parser = argparse.ArgumentParser(
        description='CTF OSINT Username Enumerator (Sherlock Lite)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s admin
  %(prog)s john_doe --threads 20
  %(prog)s the_hacker -o results.txt
""")

    parser.add_argument('username', help='The username to investigate')
    parser.add_argument('-t', '--threads', type=int, default=15, help='Number of concurrent threads (default: 15)')
    parser.add_argument('-o', '--output', help='Save discovered URLs to text file')
    
    args = parser.parse_args()
    
    # Strip illegal characters from username if necessary (basic cleanup)
    username = args.username.strip()
    
    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  Sherlock Lite\n{'─' * 60}{C.RESET}")
    print(f"  {C.BOLD}Target:{C.RESET}    {username}")
    print(f"  {C.BOLD}Platforms:{C.RESET} {len(PLATFORMS)}")
    print(f"  {C.YELLOW}⟳ Hunting across the internet...{C.RESET}\n")

    found_count = 0
    results = []

    # Run checks concurrently
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(check_site, name, conf, username): name 
            for name, conf in PLATFORMS.items()
        }
        
        for future in as_completed(futures):
            is_found, site_name, url = future.result()
            if is_found:
                found_count += 1
                results.append((site_name, url))
                # Terminal output as they come in
                print(f"  {C.GREEN}▶ {site_name:<15}{C.RESET} {url}")

    print(f"\n{C.CYAN}{'─' * 60}{C.RESET}")
    print(f"  {C.BOLD}Scan Complete.{C.RESET}")
    
    if found_count > 0:
        print(f"  {C.GREEN}Found {found_count} potential profiles.{C.RESET}")
        
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(f"Sherlock Lite Results for: {username}\n")
                    f.write("="*40 + "\n")
                    for site, uri in sorted(results):
                        f.write(f"{site}: {uri}\n")
                print(f"  {C.GREEN}Results saved to: {args.output}{C.RESET}")
            except Exception as e:
                print(f"  {C.RED}Failed to write to file: {e}{C.RESET}")
    else:
        print(f"  {C.RED}No profiles found. (Or target doesn't use these platforms){C.RESET}")
    
    print()


if __name__ == '__main__':
    main()

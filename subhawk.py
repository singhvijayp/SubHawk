import socket
import requests
from bs4 import BeautifulSoup
import argparse
import sys
import concurrent.futures
import csv
from urllib.parse import quote

def resolve_subdomain(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except socket.gaierror:
        return None

def detect_technologies(response):
    """Basic technology detection"""
    tech = []
    headers = response.headers
    
    # Server header
    if 'Server' in headers:
        tech.append(headers['Server'])
    
    # Common frameworks / tech
    if 'X-Powered-By' in headers:
        tech.append(headers['X-Powered-By'])
    
    content = response.text.lower()
    if 'wordpress' in content or 'wp-content' in content:
        tech.append("WordPress")
    if 'laravel' in content:
        tech.append("Laravel")
    if 'django' in content:
        tech.append("Django")
    if 'react' in content or 'next.js' in content:
        tech.append("React/Next.js")
    if 'vue' in content:
        tech.append("Vue.js")
    if 'php' in headers.get('X-Powered-By', '').lower():
        tech.append("PHP")
    
    return ", ".join(set(tech)) if tech else "Unknown"

def get_http_info(subdomain, timeout=5):
    protocols = ['https://', 'http://']
    for proto in protocols:
        url = proto + subdomain
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; SubHawk/1.0)'}
            response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            
            status = response.status_code
            size = len(response.content)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string.strip() if soup.title else "No Title"
            
            tech = detect_technologies(response)
            
            return {
                'status': status,
                'title': title[:100],
                'size': size,
                'tech': tech
            }
        except requests.exceptions.RequestException:
            continue
    return None

def passive_crt_sh(domain):
    print(f"[*] Querying crt.sh for passive subdomains...")
    try:
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        resp = requests.get(url, timeout=20)
        if resp.status_code != 200:
            return []
        
        data = resp.json()
        subdomains = set()
        for entry in data:
            for sub in entry.get('name_value', '').splitlines():
                sub = sub.strip().lower()
                if sub and sub.endswith(domain) and sub != domain:
                    subdomains.add(sub)
        
        print(f"[+] Found {len(subdomains)} unique subdomains from crt.sh")
        return list(subdomains)
    except Exception as e:
        print(f"[!] crt.sh failed: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="SubHawk - Subdomain Enumerator")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", default="wordlists/subdomains.txt", help="Wordlist path")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Threads")
    parser.add_argument("-o", "--output", help="Output CSV file")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout")
    parser.add_argument("--passive", action="store_true", help="Enable passive enumeration")
    args = parser.parse_args()

    print(f"[*] SubHawk starting for: {args.domain}\n")

    all_found = []

    if args.passive:
        passive_subs = passive_crt_sh(args.domain)
        for sub in passive_subs:
            ip = resolve_subdomain(sub)
            if ip:
                info = get_http_info(sub, args.timeout)
                print(f"\n[+] Found (Passive): {sub} → {ip}")
                print(f"\nSubdomain   : {sub}")
                print(f"IP Address  : {ip}")
                if info:
                    print(f"Status      : {info['status']}")
                    print(f"Title       : {info['title']}")
                    print(f"Content Size: {info['size']} bytes")
                    print(f"Technologies: {info['tech']}")
                else:
                    print(f"Status      : N/A")
                print("-" * 70)

    # Active Enumeration
    try:
        with open(args.wordlist, 'r') as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"[*] Loaded {len(words)} potential subdomains for brute force")
    except FileNotFoundError:
        print("[!] Wordlist not found.")
        words = []

    found_count = 0
    total = len(words)

    if words:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_sub = {executor.submit(resolve_subdomain, f"{word}.{args.domain}"): word for word in words}
            
            for future in concurrent.futures.as_completed(future_to_sub):
                full_sub = f"{future_to_sub[future]}.{args.domain}"
                try:
                    ip = future.result()
                    if ip:
                        found_count += 1
                        info = get_http_info(full_sub, args.timeout)
                        
                        print(f"\n[+] Found (Active): {full_sub} → {ip}  ({found_count}/{total})")
                        print(f"\nSubdomain   : {full_sub}")
                        print(f"IP Address  : {ip}")
                        if info:
                            print(f"Status      : {info['status']}")
                            print(f"Title       : {info['title']}")
                            print(f"Content Size: {info['size']} bytes")
                            print(f"Technologies: {info['tech']}")
                        else:
                            print(f"Status      : N/A (No HTTP)")
                        print("-" * 70)
                except Exception:
                    pass

    print(f"\n[*] SubHawk finished! Total discovered: {len(all_found) + found_count}")

    # Save to CSV
    if args.output:
        # Note: CSV saving can be expanded if needed
        print(f"[+] Results exported to {args.output}")

if __name__ == "__main__":
    main()

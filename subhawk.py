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

def get_http_info(subdomain, timeout=5):
    protocols = ['https://', 'http://']
    for proto in protocols:
        url = proto + subdomain
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; SubHawk/1.0)'}
            response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            status = response.status_code
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string.strip() if soup.title else "No Title"
            return {'status': status, 'title': title[:100]}
        except requests.exceptions.RequestException:
            continue
    return None

def passive_crt_sh(domain):
    """Passive enumeration using crt.sh"""
    print(f"[*] Querying crt.sh for passive subdomains...")
    try:
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        resp = requests.get(url, timeout=20)
        if resp.status_code != 200:
            print("[!] crt.sh returned non-200 status")
            return []
        
        data = resp.json()
        subdomains = set()
        for entry in data:
            name_value = entry.get('name_value', '')
            for sub in name_value.splitlines():
                sub = sub.strip().lower()
                if sub and sub.endswith(domain) and sub != domain:
                    subdomains.add(sub)
        
        print(f"[+] Found {len(subdomains)} unique subdomains from crt.sh")
        return list(subdomains)
    except Exception as e:
        print(f"[!] crt.sh query failed: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="SubHawk - Subdomain Enumerator")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", default="wordlists/subdomains.txt", help="Path to wordlist")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads")
    parser.add_argument("-o", "--output", help="Output file (CSV)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout in seconds")
    parser.add_argument("--passive", action="store_true", help="Enable passive enumeration using crt.sh")
    args = parser.parse_args()

    print(f"[*] SubHawk starting for domain: {args.domain}\n")

    all_found = []   # Final results list

    # === 1. Passive Enumeration ===
    if args.passive:
        passive_subs = passive_crt_sh(args.domain)
        print(f"[*] Checking HTTP info for {len(passive_subs)} passive subdomains...\n")
        
        for sub in passive_subs:
            ip = resolve_subdomain(sub)
            if ip:
                http_info = get_http_info(sub, args.timeout)
                print(f"[+] Found (Passive): {sub} → {ip}")
                print(f"\nSubdomain  : {sub}")
                print(f"IP Address : {ip}")
                if http_info:
                    print(f"Status     : {http_info['status']}")
                    print(f"Title      : {http_info['title']}")
                    all_found.append({
                        'subdomain': sub,
                        'ip': ip,
                        'status': http_info['status'],
                        'title': http_info['title']
                    })
                else:
                    print(f"Status     : N/A (No HTTP)")
                    print(f"Title      : N/A")
                    all_found.append({
                        'subdomain': sub,
                        'ip': ip,
                        'status': 'N/A (No HTTP)',
                        'title': 'N/A'
                    })
                print("-" * 60)

    # === 2. Active Brute Force ===
    try:
        with open(args.wordlist, 'r') as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"[*] Loaded {len(words)} potential subdomains for brute-force")
    except FileNotFoundError:
        print("[!] Wordlist not found. Skipping active enumeration.")
        words = []

    found_count = 0
    total = len(words)

    if words:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_sub = {
                executor.submit(resolve_subdomain, f"{word}.{args.domain}"): word 
                for word in words
            }
            
            for future in concurrent.futures.as_completed(future_to_sub):
                subdomain = future_to_sub[future]
                full_sub = f"{subdomain}.{args.domain}"
                
                try:
                    ip = future.result()
                    if ip:
                        found_count += 1
                        http_info = get_http_info(full_sub, args.timeout)
                        
                        print(f"\n[+] Found (Active): {full_sub} → {ip}  ({found_count}/{total})")
                        print(f"\nSubdomain  : {full_sub}")
                        print(f"IP Address : {ip}")
                        if http_info:
                            print(f"Status     : {http_info['status']}")
                            print(f"Title      : {http_info['title']}")
                            all_found.append({
                                'subdomain': full_sub,
                                'ip': ip,
                                'status': http_info['status'],
                                'title': http_info['title']
                            })
                        else:
                            print(f"Status     : N/A (No HTTP)")
                            print(f"Title      : N/A")
                            all_found.append({
                                'subdomain': full_sub,
                                'ip': ip,
                                'status': 'N/A (No HTTP)',
                                'title': 'N/A'
                            })
                        print("-" * 60)
                except Exception:
                    pass

    print(f"\n[*] SubHawk enumeration complete! Total live subdomains: {len(all_found)}")

    if args.output and all_found:
        with open(args.output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['subdomain', 'ip', 'status', 'title'])
            writer.writeheader()
            writer.writerows(all_found)
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
# SubHawk 🦅

**SubHawk** is a fast and easy-to-use Subdomain Enumeration tool built in Python for bug hunters and penetration testers.

It combines **Active Brute-Force** and **Passive Enumeration** (crt.sh) to discover subdomains, check their HTTP status and extract page titles.

---

## Features

- Active enumeration (DNS brute-force)
- Passive enumeration using **crt.sh**
- HTTP status code + webpage title extraction
- Multi-threaded scanning
- Clean vertical output format
- Results export to CSV
- Simple and clean CLI

---

## Installation


1. Clone or download the project
```
git clone https://github.com/singhvijayp/SubHawk.git
cd SubHawk
```

3. Install dependencies
```
pip install -r requirements.txt
```

## Project Structure
```
SubHawk/
├── subhawk.py                 # Main tool
├── requirements.txt
├── wordlists/
│   └── subdomains.txt         # Default wordlist
└── README.md
```

## Usage
Basic Active Scan
```
python subhawk.py -d example.com
```
With Passive Enumeration (Recommended)
```
python subhawk.py -d example.com --passive
```
Full Command Example
```
python subhawk.py -d google.com \
  --passive \
  -t 50 \
  -o google_results.csv \
  --timeout 6
```

## Command Line Options

| Option | Description | Default Value |
|------|-----|------|
| -d, --domain | Target domain (required) | - |
| -w, --wordlist | Wordlist path | wordlists/subdomains.txt |
| -t, --threads | Number of concurrent threads | 20 |
| -o, --output | Save results to CSV file | - |
| --passive | Enable crt.sh passive enumeration | Disabled |
| --timeout | HTTP request timeout in seconds | 5 |

## Example Output
```
[*] SubHawk starting for domain: example.com

[*] Querying crt.sh for passive subdomains...
[+] Found 42 unique subdomains from crt.sh

[+] Found (Active): api.example.com → 93.184.216.34  (12/520)

Subdomain  : api.example.com
IP Address : 93.184.216.34
Status     : 200
Title      : Example API
------------------------------------------------------------
```

## Requirements
```
requests
beautifulsoup4
tqdm
```

## Tips & Best Practices
- Always use ```--passive``` first — it's faster and stealthier.
- Combine passive + active for best coverage.
- Use larger wordlists for more aggressive scanning.
- Increase threads (```-t 50```) for faster scans on good connections.
- Export results with ```-o``` for later analysis.

## Future Enhancements
- Additional passive sources (VirusTotal, etc.)
- HTML/PDF report generation
- Wildcard subdomain detection
- Screenshot module
- Proxy & rate limiting support

### Happy Hunting 🦅

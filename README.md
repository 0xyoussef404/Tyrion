# 0xMarvul RECON FLOW

![0xMarvul RECON FLOW](New_0xMarvul.png)

A comprehensive bash-based reconnaissance automation tool for bug bounty hunting and security assessments. This tool automates the process of subdomain enumeration, live host discovery, URL gathering, and sensitive file detection.

## Features

- **Automated Subdomain Enumeration** — Multiple sources: Subfinder, Assetfinder, crt.sh, Shrewdeye, HackerTarget, RapidDNS, Anubis-DB
- **Parallel Mode** — Run all enumeration tools simultaneously with `-parallel`
- **Active Subdomain Bruteforce** — dnsx + SecLists 20k wordlist with automatic wildcard DNS detection
- **Live Host Detection** — httpx single pass: produces both clean URLs and detailed info (status, title, server, size)
- **Technology Detection** — Detects CMS, frameworks, and web servers
- **URL Discovery** — Gospider, Waybackurls, Katana — all properly merged into `allurls.txt`
- **Extended URL Discovery** — GAU and Hakrawler with `-moreurls`
- **URL Cleanup** — Filters junk extensions (images, fonts, media) while keeping `.pdf` and `.zip`
- **Parameter Discovery** — ParamSpider with robust output detection across all versions
- **JS/PHP/JSON/BIGRAC Filtering** — Automatic categorization of sensitive file types
- **GF Patterns** — Filter URLs by vulnerability type (XSS, SQLi, SSRF, LFI, RCE, IDOR, SSTI)
- **Grep Juicy URLs** — Categorized extraction: configs, backups, secrets, admin panels, APIs, cloud, etc.
- **Directory Bruteforce** — Dirsearch with your custom wordlist or default
- **Secret Finding** — SecretFinder scans JavaScript files for leaked secrets
- **Screenshot Capture** — Gowitness screenshots all live hosts + generates HTML report
- **Port Scanning** — Naabu fast discovery + Nmap service detection
- **Subdomain Takeover** — Nuclei with takeover templates
- **Discord Notifications** — Real-time alerts: scan start, completion, tool errors, critical takeovers
- **ENTER to skip** — Skip any long-running tool instantly, partial results saved
- **P to pause / C to resume** — Freeze the entire scan (SIGSTOP) and continue (SIGCONT)
- **Checkpoint / Resume** — Automatically resumes from last completed step after any interruption
- **Dynamic Progress Counter** — `[3/9]` steps based on your enabled flags
- **Smart Summary** — Only shows files that exist and have content, with line counts
- **@ Filter** — Automatically removes email-style noise from subdomain results

---

## Checkpoint / Resume System

The most powerful feature — your scan **never starts from zero** after an interruption.

### How it works

After each step fully completes, its key is written to `target.com/.checkpoint`. If the scan is interrupted for **any reason**:

- `Ctrl+C` — trap fires, saves last completed step immediately
- Power cut / `kill -9` — heartbeat writes checkpoint every 2 seconds
- Internet loss — tools fail/timeout gracefully, scan continues
- Laptop closed / suspended — resumes from checkpoint on next run

### Resuming

Just run the exact same command again:

```bash
./0xMarvul_RECON_FLOW.sh target.com -moreurls -gf -grep
```

The script detects the checkpoint and resumes automatically:

```
  [!] Previous scan found for target.com — resuming automatically
  [*] Completed steps will be skipped

  [*] ⏭  Skipping: Subdomain Enumeration (already completed)
  [*] ⏭  Skipping: DNS Resolution (already completed)
  [*] ⏭  Skipping: Live Host Check (already completed)

  ┌─────────────────────────────────────────────────────┐
  │  [4/9] URL Gathering
  │  Started: 14:32:01
  └─────────────────────────────────────────────────────┘
```

### Directory behavior

| Situation | What happens |
|-----------|-------------|
| Checkpoint found | Resumes automatically — no questions asked |
| No checkpoint, `all_subs.txt` exists | Previous scan completed — asks before overwriting |
| No directory at all | Fresh target — creates directory and runs |

### Important notes

- Checkpoint is saved **per completed step** — if interrupted mid-step, that step reruns from scratch (safe — no partial data)
- Checkpoint file is deleted automatically when scan completes successfully
- To rescan a finished target: delete the `target.com/` folder and run again

---

## Skip / Pause / Continue

Every long-running tool shows:

```
  [*] Running Katana...
  ↵  ENTER to skip  |  P to pause
```

| Key | Action |
|-----|--------|
| `ENTER` | Skip current tool — saves partial results, moves to next |
| `P` | Pause entire scan — freezes tool + all child processes (zero CPU) |
| `C` | Resume scan — continues exactly where it stopped |

---

## Prerequisites

### Required Tools

1. **Subfinder**
   ```bash
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   ```

2. **Assetfinder**
   ```bash
   go install github.com/tomnomnom/assetfinder@latest
   ```

3. **httpx**
   ```bash
   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
   ```

4. **Gospider**
   ```bash
   go install github.com/jaeles-project/gospider@latest
   ```

5. **Waybackurls**
   ```bash
   go install github.com/tomnomnom/waybackurls@latest
   ```

6. **Katana**
   ```bash
   go install github.com/projectdiscovery/katana/cmd/katana@latest
   ```

7. **ParamSpider**
   ```bash
   pip install paramspider
   ```

8. **jq**
   ```bash
   sudo apt-get install jq
   ```

9. **curl**
   ```bash
   sudo apt-get install curl
   ```

### Optional Tools

10. **Dirsearch** (for `-dir` flag)
    ```bash
    pip install dirsearch
    ```

11. **SecretFinder** (for `-secret` flag)
    ```bash
    git clone https://github.com/m4ll0k/SecretFinder.git
    cd SecretFinder
    pip install -r requirements.txt
    sudo ln -s $(pwd)/SecretFinder.py /usr/local/bin/secretfinder
    sudo chmod +x /usr/local/bin/secretfinder
    ```

12. **Gowitness** (for `-gowitness` flag)
    ```bash
    go install github.com/sensepost/gowitness/v3@latest
    ```

13. **Nuclei** (for `-takeover` flag)
    ```bash
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    nuclei -update-templates
    ```

14. **GF + Patterns** (for `-gf` flag)
    ```bash
    go install github.com/tomnomnom/gf@latest
    git clone https://github.com/1ndianl33t/Gf-Patterns.git
    mkdir -p ~/.gf && cp Gf-Patterns/*.json ~/.gf/
    ```

15. **GAU** (for `-moreurls` flag)
    ```bash
    go install github.com/lc/gau/v2/cmd/gau@latest
    ```

16. **Hakrawler** (for `-moreurls` flag)
    ```bash
    go install github.com/hakluke/hakrawler@latest
    ```

17. **Naabu** (for `-port` flag)
    ```bash
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    ```

18. **Nmap** (for `-port` flag)
    ```bash
    sudo apt-get install nmap
    ```

19. **dnsx** (for `-port` and `-bruteforce` flags)
    ```bash
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    ```

20. **SecLists** (for `-bruteforce` flag)
    ```bash
    sudo apt install seclists
    ```

### Quick Install (All Go Tools)

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/gf@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/sensepost/gowitness/v3@latest

pip install paramspider dirsearch

git clone https://github.com/m4ll0k/SecretFinder.git
cd SecretFinder && pip install -r requirements.txt
sudo ln -s $(pwd)/SecretFinder.py /usr/local/bin/secretfinder
sudo chmod +x /usr/local/bin/secretfinder && cd ..

git clone https://github.com/1ndianl33t/Gf-Patterns.git
mkdir -p ~/.gf && cp Gf-Patterns/*.json ~/.gf/

sudo apt install seclists

export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
```

---

## Installation

```bash
git clone https://github.com/0xmarvul/0xMarvul_RECON_FLOW.git
cd 0xMarvul_RECON_FLOW
chmod +x 0xMarvul_RECON_FLOW.sh
```

---

## Usage

```bash
./0xMarvul_RECON_FLOW.sh <domain> [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `-parallel` | Run subdomain enumeration tools in parallel |
| `-bruteforce` | Active subdomain bruteforce with dnsx + SecLists 20k |
| `-moreurls` | Extra URL gathering with GAU and Hakrawler |
| `-dir` | Directory bruteforce with Dirsearch (default wordlist) |
| `-dir /path/wordlist` | Directory bruteforce with custom wordlist |
| `-secret` | Find secrets in JavaScript files |
| `-takeover` | Subdomain takeover check with Nuclei |
| `-gf` | GF patterns to filter URLs by vulnerability type |
| `-grep` | Extract juicy URLs by category |
| `-port` | Port scanning with Naabu + Nmap |
| `-gowitness` | Screenshot all live hosts |
| `--webhook <url>` | Custom Discord webhook URL |
| `--no-notify` | Disable Discord notifications |

### Examples

```bash
# Basic recon
./0xMarvul_RECON_FLOW.sh target.com

# Fast + active subdomain discovery
./0xMarvul_RECON_FLOW.sh target.com -parallel -bruteforce

# Deep URL analysis
./0xMarvul_RECON_FLOW.sh target.com -moreurls -gf -grep

# Visual recon + ports
./0xMarvul_RECON_FLOW.sh target.com -gowitness -port

# Custom wordlist for directory bruteforce
./0xMarvul_RECON_FLOW.sh target.com -dir /usr/share/wordlists/dirb/big.txt

# Full scan
./0xMarvul_RECON_FLOW.sh target.com -parallel -bruteforce -moreurls -dir -secret -gf -grep -gowitness -port
```

---

## Output Structure

```
target.com/
├── .checkpoint                  # Resume file (deleted when scan completes)
├── subs_subfinder.txt           # Subdomains from Subfinder
├── subs_assetfinder.txt         # Subdomains from Assetfinder
├── subs_crtsh.txt               # Subdomains from crt.sh
├── subs_shrewdeye.txt           # Subdomains from Shrewdeye
├── subs_hackertarget.txt        # Subdomains from HackerTarget
├── subs_rapiddns.txt            # Subdomains from RapidDNS
├── subs_anubis.txt              # Subdomains from Anubis-DB
├── subs_bruteforce.txt          # Active bruteforce results (if -bruteforce)
├── all_subs.txt                 # All unique subdomains (deduplicated, @ filtered)
├── live_hosts.txt               # Clean URLs for tools
├── live_hosts_detailed.txt      # Live hosts with status, title, server, size
├── tech_detect.txt              # Detected technologies
├── gospider_output/             # Gospider crawl results
├── gospider_urls.txt            # Gospider URLs extracted and merged
├── wayback.txt                  # Wayback Machine URLs
├── katana.txt                   # Katana crawler URLs
├── gau.txt                      # GAU URLs (if -moreurls)
├── hakrawler.txt                # Hakrawler URLs (if -moreurls)
├── allurls.txt                  # All URLs combined, deduplicated, cleaned
├── params.txt                   # Parameters from ParamSpider
├── javascript.txt               # JavaScript file URLs
├── php.txt                      # PHP file URLs
├── json.txt                     # JSON file URLs
├── BIGRAC.txt                   # Sensitive files (swagger, .env, configs, etc.)
├── gowitness_output/            # Screenshots (if -gowitness)
│   ├── *.jpeg                   # Screenshots per host
│   ├── gowitness.sqlite3        # Gowitness database
│   └── report/report.html       # HTML report — open in browser
├── gf/                          # GF vulnerability patterns (if -gf)
│   ├── xss.txt
│   ├── sqli.txt
│   ├── ssrf.txt
│   ├── lfi.txt
│   ├── redirect.txt
│   ├── rce.txt
│   ├── idor.txt
│   └── ssti.txt
├── grep_results/                # Juicy URLs by category (if -grep)
│   ├── config.txt
│   ├── backup.txt
│   ├── database.txt
│   ├── secrets.txt
│   ├── sourcecode.txt
│   ├── api.txt
│   ├── admin.txt
│   ├── debug.txt
│   ├── logs.txt
│   ├── uploads.txt
│   ├── keys.txt
│   ├── datafiles.txt
│   ├── internal.txt
│   ├── cloud.txt
│   └── ALL_JUICY.txt
├── takeover_results.txt         # Takeover vulnerabilities (if -takeover)
├── secrets_found.txt            # Secrets in JS files (if -secret)
├── mar0xwan.txt                 # Dirsearch results (if -dir)
├── open_ports.txt               # Open ports (if -port)
└── ports_detailed.txt           # Nmap service scan (if -port)
```

---

## Discord Notifications

Enabled by default. Sends three types of messages:

- **Scan Started** — target and timestamp
- **Scan Completed** — full stats (subdomains, hosts, URLs, findings, duration)
- **Tool Errors** — which tool failed, scan continues
- **🚨 Critical** — instant alert if subdomain takeover found

```bash
# Custom webhook
./0xMarvul_RECON_FLOW.sh target.com --webhook "https://discord.com/api/webhooks/YOUR_ID/TOKEN"

# Disable
./0xMarvul_RECON_FLOW.sh target.com --no-notify
```

---

## BIGRAC Detection

**BIGRAC** (Bug bounty Interesting Gateways, Routes, Apis, and Configurations) automatically finds:

- Swagger / OpenAPI documentation
- Configuration files (`.env`, `config.yaml`, `config.json`)
- Database files (`db.sql`, `dump.sql`)
- Credential files (`.htpasswd`, `credentials`)
- API schemas, manifests, package files

---

## Color Coding

| Color | Meaning |
|-------|---------|
| 🟢 Green | Success |
| 🔴 Red | Error |
| 🟡 Yellow | Warning / skip-pause hints |
| 🔵 Cyan/Blue | Info and step headers `[N/TOTAL]` |
| 🟣 Magenta | Section headers (Dependencies, Output Dir, Summary) |

---

## Ethical Usage

- ✅ Authorized security testing
- ✅ Bug bounty programs
- ✅ Your own domains
- ✅ Educational purposes

**Always ensure you have permission before scanning any target.**

---

## Contributing

Contributions are welcome! Feel free to report bugs, suggest features, or submit pull requests.

## License

Open source — available for educational and ethical security testing purposes.

## Author

**Marwan Khodair** **(0xMarvul)**

## Support

If you find this tool useful, please consider giving it a ⭐ on GitHub!

## Resources

- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [Katana](https://github.com/projectdiscovery/katana)
- [Gowitness](https://github.com/sensepost/gowitness)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

*This tool aggregates data from multiple sources. Some may be temporarily unavailable. The scan continues and logs any failures.*

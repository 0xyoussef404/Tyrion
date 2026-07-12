<p align="center">
  <img src="Tyrion404.png" alt="Tyrion404" width="800"/>
</p>

<h1 align="center">Tyrion404</h1>

<p align="center">
  <b>Advanced Reconnaissance & Intelligence Tool for Bug Bounty Hunters</b><br/>
  <i>by Tyrion</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Shell-Bash-green?style=flat-square&logo=gnu-bash" />
  <img src="https://img.shields.io/badge/Platform-Linux-blue?style=flat-square&logo=linux" />
  <img src="https://img.shields.io/badge/Purpose-Bug%20Bounty-red?style=flat-square" />
  <img src="https://img.shields.io/badge/Intelligence-Layer-purple?style=flat-square" />
</p>

---

A comprehensive bash-based advanced reconnaissance tool for bug bounty hunting and security assessments — built with an **Intelligence Layer** that transforms raw recon data into **actionable attack paths**.

> **Where this is going:** Tyrion404 is the stable Bash engine. The next generation — a Go execution engine with a DAG scheduler, SQLite asset store, incremental recon, and a multi-identity authorization workspace — is planned in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## What's new in v1.1

- **Scan profiles** — one flag (`-profile passive|fast|deep|api|infra|continuous`) instead of a dozen.
- **Per-tool timeout** — every external tool is hard-capped (`-timeout`, default `20m`); a hung tool can no longer stall the whole scan.
- **Honest checkpoints** — a step that times out or fails is **not** marked complete, so re-running retries only what didn't finish (instead of silently skipping it).
- **Profile-aware dependency check** — `-doctor`-style output now only reports tools the selected profile actually uses.
- **Central log** — every tool start/end/timeout is written to `tyrion.log`.
- **Run metrics** — end-of-run summary of duration, steps completed/skipped/failed, timeouts, and tools run.
- **Input validation** — the target domain is validated before it ever reaches a shell.

## Features

### Subdomain Enumeration
- **Multi-source passive** — Subfinder, Assetfinder, crt.sh, Shrewdeye, HackerTarget, RapidDNS, Anubis-DB
- **Git sources** — github-subdomains, gitlab-subdomains
- **Chaos API** — ProjectDiscovery passive dataset
- **Crobat** — Certspotter/Sonar dataset
- **TLS certificates** — tlsx SAN/CN extraction
- **Parallel mode** — all tools simultaneously with `-parallel`
- **Bruteforce + Permutations** — dnsx + SecLists 20k + alterx/dnsgen permutation engine with puredns resolution

### Infrastructure Mapping (`-asn`)
- ASN discovery and CIDR extraction (asnmap)
- IP range enumeration
- Cloud asset detection (AWS/Azure/GCP/Firebase)
- CDN vs origin detection (cdncheck)

### Live Host Analysis
- httpx single pass — status, title, server, content-length
- Technology fingerprinting
- WAF detection per host (`-waf` via wafw00f)
- Virtual host discovery (`-vhost` via ffuf)

### URL & Parameter Intelligence
- **Crawlers** — Gospider, Katana, Cariddi
- **Archives** — Waybackurls, GAU, Hakrawler (`-moreurls`)
- **URL deduplication** — uro smart dedup
- **URL structure** — unfurl for paths/keys/domains
- **ParamSpider** — automated parameter discovery
- **Arjun** (`-arjun`) — deep active parameter mining
- **Unified parameter list** — all params ranked by frequency in `all_parameters.txt`

### JavaScript Intelligence (`-jsdeep`)
- Downloads all JS files locally
- **jsluice** — structured endpoint + secret extraction
- Regex extraction: paths, absolute URLs, API keys, tokens, Firebase configs
- Parameter mining from JS source
- Reconstructed full endpoints from JS paths × live hosts

### Attack Analysis (always-on)
- **Attack surface ranking** — HIGH / MEDIUM / LOW endpoint classification
- **Bug hunt candidates** — IDOR / SSRF / XSS / Open Redirect / LFI / SQLi pre-filtered targets
- **Auth surface detection** — login/OAuth/SAML/SSO endpoints + provider fingerprinting
- **BIGRAC** — Swagger, OpenAPI, GraphQL, .env, config, credentials auto-detection

### Vulnerability Hunting
- **GF patterns** (`-gf`) — XSS, SQLi, SSRF, LFI, RCE, IDOR, SSTI, CORS, S3 buckets
- **Grep juicy** (`-grep`) — configs, backups, secrets, admin, APIs, cloud, auth, logs
- **Nuclei full scan** (`-nuclei`) — exposures + misconfigs + CVEs + takeovers
- **Subdomain takeover** (`-takeover`) — nuclei takeover templates
- **SecretFinder** (`-secret`) — secrets in JS files
- **Dirsearch** (`-dir`) — directory bruteforce with custom wordlist support

### Active Scanning
- **Port scanning** (`-port`) — Naabu fast discovery + Nmap service detection
- **Screenshots** (`-gowitness`) — Gowitness with HTML report generation

### Reliability
- **Scan profiles** — `-profile passive|fast|deep|api|infra|continuous`
- **Per-tool timeout** — `-timeout` hard-caps every external tool (default `20m`)
- **ENTER to skip** — any long-running tool, partial results preserved
- **P to pause / C to resume** — SIGSTOP/SIGCONT control
- **Checkpoint / Resume** — auto-resumes from last completed step; failed/timed-out steps are retried, not skipped
- **Central log + run metrics** — `tyrion.log` and an end-of-run metrics summary

## Usage

```bash
./Tyrion404.sh <domain> [flags]
```

### Profiles (v1.1)

Pick one profile instead of assembling flags by hand:

| Profile | Expands to |
|---------|-----------|
| `-profile passive` | Base only — passive enum + DNS + HTTP + URLs + JS + intelligence (default) |
| `-profile fast` | passive + `-moreurls -jsdeep -gf -grep` |
| `-profile deep` | Everything — active scanning + full network intelligence |
| `-profile api` | Swagger/OpenAPI + JS APIs + `-validate -apidisc -cors -methods -verify` |
| `-profile infra` | `-parallel -asn -port -waf -takeover -vhost` |
| `-profile continuous` | Lean, re-runnable set for monitoring (leans on checkpoint + historical diff) |

### Execution control (v1.1)

| Flag | Description |
|------|-------------|
| `-timeout <dur>` | Per-tool hard timeout (default `20m`, e.g. `30m`, `600s`) |
| `-concurrency <n>` | Worker-pool parallelism (default `50`) |

`TOOL_TIMEOUT`, `KILL_AFTER`, and `CONCURRENCY` can also be set as environment variables.

### Flags

| Flag | Description |
|------|-------------|
| `-parallel` | Run subdomain tools in parallel |
| `-bruteforce` | Active bruteforce + alterx/dnsgen permutations |
| `-asn` | ASN & CIDR mapping, cloud asset detection |
| `-vhost` | Virtual host discovery (ffuf) |
| `-waf` | WAF detection (wafw00f) |
| `-moreurls` | GAU + Hakrawler extra URL sources |
| `-arjun` | Deep parameter discovery (Arjun) |
| `-jsdeep` | Download JS + extract endpoints/params/secrets |
| `-secret` | SecretFinder on JS files |
| `-gf` | GF vulnerability pattern classification |
| `-grep` | Grep juicy URLs by category |
| `-nuclei` | Full Nuclei scan (exposures + misconfigs + CVEs) |
| `-takeover` | Subdomain takeover detection |
| `-dir [wordlist]` | Dirsearch directory bruteforce |
| `-port` | Port scan (Naabu + Nmap) |
| `-gowitness` | Screenshot live hosts |

### Examples

```bash
# Basic recon (passive profile)
./Tyrion404.sh target.com

# Profiles — the easy way
./Tyrion404.sh target.com -profile fast
./Tyrion404.sh target.com -profile api -timeout 30m
./Tyrion404.sh target.com -profile deep

# Fast parallel + bruteforce + ASN
./Tyrion404.sh target.com -parallel -bruteforce -asn

# Deep URL + JS analysis
./Tyrion404.sh target.com -moreurls -jsdeep -gf -grep -arjun

# Infrastructure focus
./Tyrion404.sh target.com -asn -vhost -waf -port

# Full everything
./Tyrion404.sh target.com -parallel -moreurls -jsdeep -dir -secret -gf -grep -gowitness -nuclei -asn -vhost -waf -arjun
```

## Output Structure

```
target.com/
├── all_subs.txt                  # All unique subdomains
├── live_hosts.txt                # Live hosts (clean URLs)
├── live_hosts_detailed.txt       # Status + title + server + size
├── tech_detect.txt               # Technology fingerprints
├── cdncheck_results.txt          # CDN / origin detection
├── tyrion_waf.txt                # WAF detection
├── asn.txt / cidrs.txt           # ASN & IP ranges
├── cloud_assets.txt              # Cloud assets
├── allurls.txt                   # All URLs (deduplicated)
├── url_paths.txt                 # Unique paths (unfurl)
├── url_param_keys.txt            # Unique param keys (unfurl)
├── params.txt                    # Parameters (ParamSpider)
├── arjun_params.txt              # Parameters (Arjun)
├── all_parameters.txt            # All params ranked by frequency
├── javascript.txt                # JavaScript URLs
├── BIGRAC.txt                    # API/sensitive endpoints
├── js_files/                     # Downloaded JS files
├── js_analysis/                  # jsluice + regex extractions
├── reconstructed_endpoints/      # JS paths × live hosts
├── attack_surface/               # HIGH / MEDIUM / LOW ranked
├── bug_hunt/                     # IDOR / SSRF / XSS / LFI / SQLi
├── auth_surface/                 # Auth endpoints & providers
├── grep_results/                 # Juicy URLs by category
├── gf/                           # GF pattern results
├── vhost_results/                # Virtual host findings
├── gowitness_output/             # Screenshots + HTML report
├── tyrion_dirsearch.txt          # Dirsearch results
├── tyrion_nuclei.txt             # Nuclei findings
├── takeover_results.txt          # Takeover vulnerabilities
├── secrets_found.txt             # JS secrets
├── open_ports.txt                # Open ports (Naabu)
├── ports_detailed.txt            # Service details (Nmap)
├── tyrion.log                    # Central run log (tool start/end/timeout)
├── .checkpoint                   # Resume state (removed on a clean finish)
└── .cache/                       # dns/ http/ js/ swagger/ nuclei/ cache dirs
```

## Author

**Tyrion**

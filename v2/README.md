# Tyrion V2 — Recon & Offensive Intelligence Platform

A ground-up rewrite of Tyrion as a **platform** for bug-bounty recon and offensive
intelligence, shipped as a **single dependency-free Go binary** (standard library
only, no CGO — builds and runs fully offline). The legacy Bash engine
(`Tyrion404.sh`) is still supported at the repo root.

```
Project → Scope → Asset Graph → DAG Pipeline → Intelligence → Testing → Findings → Reports
```

---

## Build & install

```bash
cd v2
go build -o tyrion ./cmd/tyrion     # single static binary, no deps
make install                        # or: copies to ~/go/bin
```

Point the binary at the plugin definitions (only needed if not run from `v2/`):

```bash
export TYRION_PLUGINS=/path/to/v2/plugins
```

---

## Everything it does (feature map)

### Recon pipeline (22 tool plugins, DAG-scheduled)
- **Subdomain enum** — subfinder, assetfinder, tlsx, alterx, dnsgen
- **DNS resolution / liveness** — dnsx
- **HTTP probing** — httpx (status, title, tech, server, favicon → `http_services`)
- **Crawling** — katana, gospider, hakrawler
- **Archive URLs** — gau, waybackurls
- **Deep JS analysis** — fetches JS, extracts endpoints, API bases, secrets, GraphQL hints
- **Port scan / ASN / CDN** — naabu, asnmap, cdncheck
- **Nuclei / takeover** — nuclei, nuclei (takeover tag)
- **Content discovery / XSS** — ffuf, dalfox, kxss
- **Screenshots** — gowitness

### Intelligence layer (more data for hunting)
- **Endpoint normalization** — `/api/users/{integer}`, `{uuid}`, `{mongoid}`, `{hash}`, `{jwt}`, …
- **IDOR-candidate detection** — object-id routes flagged automatically
- **0–100 scoring** — explainable components (asset value, sensitivity, auth surface, tech risk, novelty, param risk, response signal)
- **Vulnerability classifier (gf-style)** — buckets URLs into xss / sqli / ssrf / lfi / open-redirect / rce / ssti / idor
- **Parameter mining** — frequency-ranked param wordlist for fuzzing
- **Juicy-path grep** — config / backup / secret / vcs / api / admin / debug / upload
- **Secret extraction** — 16 patterns (AWS/GCP/Stripe/GitHub/Slack/JWT/private keys/Firebase/…) with confidence + masking
- **Swagger/OpenAPI parsing** — paths/methods/params/security → endpoints + curl collection + unauth list
- **GraphQL** — introspection-probe generation + operation-impact classification
- **Asset-graph correlation** — shared-favicon / shared-cert clusters (hidden infra)
- **Tech playbooks** — turns fingerprints (Spring, Jenkins, GitLab, Grafana, Laravel, …) into concrete attack paths
- **Dork generator** — Google / GitHub / Shodan queries (+ favicon → Shodan pivot)

### Offensive testing workspace
- **Multi-identity authorization comparator** — replays a request across identities, flags BFLA/broken access control with confidence
- **State-change detector** — GET-before / mutate / GET-after diff to confirm candidate → confirmed
- **BOLA batch mode** — auto-tests every IDOR/sensitive endpoint across identities
- **CORS misconfiguration checker** — reflected-origin / null-origin / wildcard + credentials
- **401/403 bypass generator** — 11 path tricks + 9 header spoofs, actively tested
- **Security-header analysis** — flags missing CSP/HSTS/XFO/…
- **Findings + evidence vault** — automatic secret/PII redaction, PoC packs

### Platform
- **DAG engine** — concurrent, per-task timeout, cycle detection, fingerprint cache (incremental)
- **Dependency-free store** — JSONL source of truth + query DSL, txt/json export
- **Scope engine** — wildcard include/exclude, enforced everywhere
- **Scan profiles** — one flag instead of dozens
- **Config file** — `tyrion.yaml` / `~/.tyrion.yaml` for defaults + API keys
- **Notifications** — outbound webhook (Slack/Discord/generic)
- **Continuous monitoring** — `watch` loop with webhook alerts on delta
- **Web dashboard** — `serve`: JSON API + single-page UI with **light/dark mode**
- **Plugin system** — add a tool by dropping a YAML file

---

## How to run it

### Full power (everything)

```bash
./tyrion scan target.com -profile deep -concurrency 50 -o out
```

`deep` runs: subdomain enum → DNS → ASN → HTTP → ports → crawl → archives → JS →
Swagger → GraphQL → nuclei → takeover → screenshots → auth-surface → normalize →
score → correlate → vuln-classify → param-mine → juicy → CORS → security-headers →
report.

### Targeted (specific things only) — pick a profile

```bash
./tyrion scan target.com -profile passive     # passive only, no active probing
./tyrion scan target.com -profile fast        # + crawl + JS + vuln classification
./tyrion scan target.com -profile api         # Swagger/GraphQL/JS APIs + CORS
./tyrion scan target.com -profile infra       # ASN + ports + takeover
./tyrion scan target.com -profile continuous  # lean, re-runnable (for monitoring)
```

| Profile | Focus |
|---------|-------|
| `passive` | Passive enum + DNS + HTTP + intelligence (no active probing) |
| `fast` | passive + crawl + JS + vuln-classify + param-mine + juicy |
| `deep` | Everything: active scanning + full intelligence + active checks |
| `api` | Swagger + GraphQL + JS APIs + vuln-classify + param-mine + CORS |
| `infra` | ASN + ports + takeover + correlation |
| `continuous` | Lean re-runnable set for monitoring |

Tune with `-concurrency <n>`, `-timeout <dur>`, `-scope <file>`, `-o <dir>`.

### Query & explore the results

```bash
./tyrion assets target.com
./tyrion endpoints target.com                 # ranked by score
./tyrion secrets target.com
./tyrion params target.com                    # fuzzing wordlist
./tyrion juicy target.com                     # juicy URLs by category
./tyrion playbook target.com                  # attack paths from detected tech
./tyrion graph target.com                     # shared-favicon/cert clusters
./tyrion query target.com endpoints "score>50 and template contains api"
./tyrion export target.com urls --format txt
./tyrion report target.com                    # regenerate REPORT.md
```

### Offensive testing

```bash
# Register identities
./tyrion identity target.com add anonymous -priv 0
./tyrion identity target.com add low  -priv 10 -header "Authorization: Bearer <low-JWT>"
./tyrion identity target.com add admin -priv 100 -header "Authorization: Bearer <admin-JWT>"

# One request across all identities (BFLA)
./tyrion authz target.com request.txt

# + confirm the mutation actually changed state (candidate -> confirmed)
./tyrion authz target.com mutate.txt -read read.txt

# Auto-test every IDOR/sensitive endpoint (BOLA workspace)
./tyrion authz-batch target.com -base https://api.target.com

# One-off active checks
./tyrion bypass https://target.com/admin      # 401/403 bypass techniques
./tyrion cors   https://api.target.com/data    # CORS misconfiguration
./tyrion dorks  target.com                     # search dorks
```

`request.txt` format:

```
POST https://api.target.com/api/role/addRole
Content-Type: application/json

{"role":"admin"}
```

### Continuous monitoring + dashboard

```bash
./tyrion monitor target.com                    # one incremental pass, prints delta
./tyrion watch target.com -interval 6h         # loop forever, webhook on new hosts
./tyrion serve                                 # dashboard on http://127.0.0.1:8088
```

### Tool health

```bash
./tyrion doctor                                # which of the 22 tools are installed
./tyrion plugin list
```

---

## Config file (`tyrion.yaml` or `~/.tyrion.yaml`)

```yaml
profile: fast
concurrency: 40
timeout: 25m
webhook: https://hooks.slack.com/services/XXX     # or export TYRION_WEBHOOK
env_CHAOS_KEY: your-chaos-key                      # exported to tools at runtime
env_GITHUB_TOKEN: ghp_xxx
```

CLI flags always override the config file.

---

## Adding a tool

Drop a YAML file in `plugins/` — no core changes:

```yaml
name: subfinder
category: subdomain-enumeration
binary: subfinder
args: ["-d", "{{target}}", "-silent"]
parser: host-lines        # lines | host-lines | json (+ field:)
timeout: 10m
# stdin_file: "{{infile}}"   # pipe a file to the tool's stdin instead
```

`{{target}}` and `{{infile}}` are substituted at run time.

---

## Architecture

| Package | Responsibility |
|---------|----------------|
| `internal/model` | Typed entities (assets, services, urls, endpoints, params, secrets, findings, identities, edges) |
| `internal/store` | Dependency-free JSONL store + query DSL (source of truth) |
| `internal/scope` | Include/exclude scope enforcement |
| `internal/config` | Scan profiles + config-file loader |
| `internal/pluginfmt` | Minimal YAML parser for plugin files |
| `internal/tools` | Plugin loader + subprocess runner |
| `internal/engine` | Concurrent DAG scheduler + fingerprint cache |
| `internal/httpx` | Shared HTTP client (cookie jar, response cache, per-host rate limit, backoff) |
| `internal/intel` | Normalization, scoring, correlation, secrets, JS, Swagger, GraphQL, classify, params, juicy, dorks, playbooks |
| `internal/active` | CORS check, 401/403 bypass, security-header analysis |
| `internal/authz` | Multi-identity comparator + state-change detector |
| `internal/notify` | Outbound webhook notifications |
| `internal/findings` | Findings + evidence vault + redaction |
| `internal/reporting` | Markdown reports + PoC packs |
| `internal/pipeline` | Wires stages into the DAG |
| `internal/server` | JSON API + dashboard (light/dark) |
| `cmd/tyrion` | CLI |
| `plugins/*.yaml` | 22 tool definitions |

---

## Tests

```bash
go test ./...     # engine, store/query DSL, plugin parser, normalization, scoring,
                  # secrets, JS, Swagger 2/3, GraphQL, classify/juicy/params/dorks,
                  # authz comparator, state-change, CORS + 403-bypass (httptest)
```

All checks run offline. `go vet` and `gofmt` are clean.

See [`../docs/PLATFORM.md`](../docs/PLATFORM.md) for the full feature map and
[`../docs/ROADMAP.md`](../docs/ROADMAP.md) for what's planned next.

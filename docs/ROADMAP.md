# Tyrion Roadmap

Tyrion is evolving from a single Bash recon script into a recon **platform**. The
guiding shift is from a flat pipeline:

```
Domain → Tools → Text Files
```

to a data model that treats a target as a living project:

```
Project
  ↓
Scope Engine
  ↓
Asset Graph
  ↓
Dynamic Recon Pipeline
  ↓
Intelligence & Correlation
  ↓
Testing Workspace
  ↓
Findings & Evidence
  ↓
Reports & Retests
```

`Tyrion404.sh` stays as the stable, supported **legacy engine**. Tyrion V2 is a new
codebase, not an extension of the Bash script.

---

## Target architecture (V2)

```
tyrion/
├── cmd/tyrion/          # CLI entrypoint
├── internal/
│   ├── engine/          # DAG scheduler / task runner
│   ├── scope/           # scope parsing & enforcement
│   ├── assets/          # asset inventory + graph
│   ├── pipeline/        # recon stages as tasks
│   ├── tools/           # plugin runner (subprocess adapters)
│   ├── intelligence/    # scoring, correlation, normalization
│   ├── findings/        # findings + evidence vault
│   └── reporting/       # report + retest generation
├── configs/
├── templates/
├── web/                 # dashboard (Go API + React/Vite)
└── plugins/             # tool definitions (YAML)
```

### Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Execution engine | **Go** | speed, strong concurrency, single binary, low RAM, easy subprocess control, same ecosystem as ProjectDiscovery |
| Intelligence engine | **Python** (optional service) | semantic similarity, duplicate detection, endpoint classification, report generation, secret confidence scoring |
| Storage | **SQLite** (CLI) → **PostgreSQL** (server) | queryable source of truth; text files become an export format |
| Dashboard | **Go API + React/Vite** (or Angular) | local dashboard once the CLI is stable |

---

## Core V2 ideas

### 1. DAG execution engine
Replace fixed sequential stages with tasks that declare inputs, outputs, and
dependencies. Independent branches (ASN discovery, GitHub recon, cloud enumeration)
run in parallel with the HTTP-probing branch instead of waiting behind it.

```yaml
id: http-probe
depends_on: [dns-resolution]
inputs:  [resolved_hosts]
outputs: [http_services]
concurrency: 100
timeout: 15m
cache: true
```

### 2. Scan profiles
Ship ready-made profiles (`passive`, `fast`, `deep`, `api`, `infra`, `continuous`)
instead of dozens of flags. *(Already delivered in v1.1 for the Bash engine.)*

### 3. Incremental recon (fingerprints)
Every asset gets a fingerprint (DNS hash, HTTP hash, content hash, JS hash, ports,
tech). Before running expensive scans (Katana, Nuclei), skip anything that has not
changed. `tyrion monitor <domain>` reports the delta (new subdomains/APIs/JS/ports,
dead hosts, changed responses) rather than re-scanning from zero.

### 4. Database as source of truth
SQLite tables (`projects`, `scopes`, `assets`, `dns_records`, `http_services`,
`ports`, `technologies`, `urls`, `endpoints`, `parameters`, `javascript_files`,
`secrets`, `scan_runs`, `tool_runs`, `findings`, `evidence`) with `tyrion export`
for txt/json/markdown compatibility and a `tyrion query` DSL.

### 5. Asset graph + correlation
Store relationships (`DOMAIN_RESOLVES_TO_IP`, `HOST_USES_TECH`,
`JS_REFERENCES_ENDPOINT`, `HOST_SHARES_CERTIFICATE`, `HOST_SHARES_FAVICON`,
`IP_BELONGS_TO_ASN`, …) so shared-favicon / shared-cert clusters surface related
infrastructure automatically.

### 6. Plugin system
Tools become YAML definitions (`plugins/subfinder.yaml`, …) with `binary`,
`command`, `parser`, `timeout`, `rate_limit`. New tools require no core changes:
`tyrion plugin install|list|disable`.

### 7. Tool health manager
`tyrion doctor` reports installed/outdated tools, template age, configured API keys,
resolver health, disk space. `tyrion update [--tools|--templates]`. Dependency
checks are scoped to the **selected profile only**. *(Profile-scoped dep check
delivered in v1.1.)*

### 8. Smart rate limiting
Per-host rate limiters, global + per-host concurrency, retry with backoff, 429/503
detection, WAF-slowdown and circuit-breaker behaviour.

### 9. Central HTTP service
A single shared HTTP layer (request/response cache, shared cookie jar, shared DNS
resolver, shared rate limiter) so httpx, CORS checks, method checks, tech detection,
and verifiers stop re-requesting the same URL.

### 10. Endpoint normalization
Collapse `/api/users/{integer}`, `/order/{uuid}`, etc. by detecting variable types
(integer, uuid, email, date, hash, base64, JWT, Mongo ObjectId). Feeds IDOR
candidates, parameter mining, dedup, Swagger correlation, and reports.

### 11. API intelligence
Swagger/OpenAPI + GraphQL parsers that extract methods, paths, params, auth schemes,
roles, deprecated/hidden versions, and emit Postman/Burp/OpenAPI attack collections.
GraphQL operations are classified (read/write/financial/administrative/IDOR-input).

### 12. Multi-identity authorization testing (killer feature)
Register identities (`anonymous`, `zero-user`, `normal-user`, `admin`) and replay a
request across all of them, comparing status, body schema, JSON fields, length,
semantic similarity, state change, and created object IDs to flag BFLA / missing
authorization with a confidence score.

### 13. State-change detector
GET the target object before and after a mutating request and diff it, so a finding
moves from *potential* to *confirmed*.

### 14. Evidence vault
Every test stores raw request/response, identity, timestamp, tool version, command,
screenshot, before/after state, created object, and cleanup result — with automatic
redaction of JWTs, cookies, API keys, auth headers, and emails.
`tyrion evidence pack FIND-102` produces a self-contained PoC bundle.

### 15. Intelligence scoring
Score endpoints out of 100 from components (asset value, endpoint sensitivity, auth
surface, tech risk, historical novelty, parameter risk, response signals) instead of
flat HIGH/MEDIUM/LOW.

### 16. Finding correlation & dedup
Fingerprint findings (service, route, controller, operation, auth boundary, role,
object type, root cause, impact) and report similarity to prior findings with a
shared/different breakdown.

### 17. Web dashboard & distributed mode
`tyrion serve` for a local dashboard; a controller + workers model
(`tyrion worker join`) so large scans span multiple VPSs.

---

## Delivery order

### Tyrion 1.1 — harden the current Bash engine ✅ (in progress / shipped)
- [x] Exit-code / failure-aware checkpoints (failed steps are not marked done)
- [x] Per-tool timeout (`-timeout`, `timeout` wrapper on every external tool)
- [x] Scan profiles (`-profile passive|fast|deep|api|infra|continuous`)
- [x] Profile-aware dependency check
- [x] Central logging (`tyrion.log`)
- [x] Run metrics / benchmarking summary
- [x] Cache directory scaffold (`.cache/`)
- [x] Target-domain input validation
- [ ] JSONL as the primary output format (txt generated for compatibility)
- [ ] Worker-pool fan-out (`xargs -P` / GNU parallel) for per-host loops
- [ ] Response/DNS/JS cache actually populated and consulted

### Tyrion 2.0 — Go CLI
Project/scan model · SQLite · scope engine · plugin runner · DAG scheduler · asset
inventory · incremental scans · export compatibility.

### Tyrion 2.1 — Intelligence
Endpoint normalization · asset graph · smart scoring · Swagger/GraphQL parser · JS
correlation · historical diff.

### Tyrion 2.2 — Pentest workflow
Identity profiles · authorization comparator · evidence vault · finding management ·
duplicate detection · report generator · retesting.

### Tyrion 3.0 — Platform
Web dashboard · distributed workers · team collaboration · notifications · continuous
monitoring.

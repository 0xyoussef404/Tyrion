# Tyrion Platform — Design & Feature Map

This document is the company-grade product spec for Tyrion V2. It records the
full feature surface, what is implemented today, and what is planned. For the
delivery timeline see [`ROADMAP.md`](ROADMAP.md).

Legend: ✅ implemented · 🟡 partial · ⬜ planned

---

## 1. Product shape

Tyrion is a self-hosted offensive-recon platform. A single Go binary provides
the engine, storage, intelligence, and dashboard; external recon tools plug in
as YAML definitions. It is built to run offline (no cloud dependency) and to
scale from a laptop to a distributed fleet.

```
Project → Scope Engine → Asset Graph → DAG Pipeline → Intelligence → Testing Workspace → Findings & Evidence → Reports & Retests
```

---

## 2. Execution & data core

| Feature | Status | Notes |
|---------|:--:|-------|
| Project/scan model | ✅ | Each target is a project dir with its own store, cache, artifacts |
| DAG execution engine | ✅ | Topological, concurrent waves, per-task timeout, cycle detection |
| Fingerprint cache (incremental recon) | ✅ | `engine.FileCache`; unchanged work is skipped by cache key |
| Dependency-free store (source of truth) | ✅ | JSONL per entity + in-memory generic model |
| Query DSL | ✅ | `and/or`, `=`,`!=`,`contains`,`in [..]`,`>`,`<`,`>=`,`<=` |
| Export (txt/json) | ✅ | Text files are an export format, not the store |
| Scope engine (include/exclude, wildcards) | ✅ | Enforced on every discovered host/URL |
| Scan profiles | ✅ | passive, fast, deep, api, infra, continuous |
| Central logging + run metrics | ✅ | `scan_runs` / `tool_runs` records |
| Distributed workers (controller + join) | ⬜ | Interface planned; store is already location-independent |
| PostgreSQL backend for team scale | ⬜ | Store interface can back onto SQL later |

---

## 3. Recon pipeline (plugin-driven)

| Stage | Status | Tool(s) |
|-------|:--:|--------|
| Subdomain enumeration | ✅ | subfinder, assetfinder, tlsx, alterx, dnsgen (+ any plugin) |
| DNS resolution / liveness | ✅ | dnsx |
| HTTP probing (status/title/tech/favicon) | ✅ | httpx (JSON parsed into `http_services`) |
| Crawling | ✅ | katana, gospider, hakrawler |
| Archive URLs | ✅ | gau, waybackurls |
| Deep JS analysis (endpoints/secrets/api bases) | ✅ | fetches JS via shared client, extracts endpoints + secrets + API bases |
| Port scanning | ✅ | naabu |
| ASN / infra mapping | ✅ | asnmap, cdncheck |
| Nuclei / takeover | ✅ | nuclei, nuclei (takeover tag) |
| Content discovery / XSS | ✅ | ffuf, dalfox, kxss plugins |
| Screenshots | ✅ | gowitness (raw output captured) |
| Swagger / OpenAPI parsing | ✅ | full path/method/param/security extraction + curl collection + unauth list |
| GraphQL analysis | ✅ | introspection probe generation + operation-impact classification |
| Plugin system (add tool = add file) | ✅ | `plugins/*.yaml` (22 tools), placeholders, stdin, parsers |
| Tool health manager (`doctor`) | ✅ | installed/missing per plugin; profile-scoped hint |
| Plugin install/disable from CLI | ⬜ | `plugin list` done; install/disable planned |
| Per-host smart rate limiting | ✅ | in `httpx` client (per-host interval + 429/503 backoff) |

---

## 4. Intelligence & correlation

| Feature | Status | Notes |
|---------|:--:|-------|
| Endpoint normalization | ✅ | integer, uuid, mongoid, hash, email, date, jwt, base64, slug |
| IDOR-candidate detection | ✅ | object-id routes flagged |
| 0–100 scoring with component breakdown | ✅ | asset value, sensitivity, auth surface, tech risk, novelty, param risk, response signal |
| Asset graph + edges | ✅ | resolves-to, shares-favicon, shares-cert, behind-CDN, belongs-to-ASN |
| Favicon / TLS-cert correlation clusters | ✅ | surfaces related/hidden infrastructure |
| Finding fingerprint + duplicate detection | ✅ | exact fingerprint + token similarity |
| Historical diff | 🟡 | `monitor` reports host delta; response-hash diff planned |
| Secret extraction + confidence scoring | ✅ | 16 secret patterns, denylist, masking, prod-context boost |
| Python intelligence microservice | ⬜ | optional service for semantic dedup, endpoint classification |

---

## 5. Testing workspace (offensive)

| Feature | Status | Notes |
|---------|:--:|-------|
| Identity registry | ✅ | anonymous/low-priv/admin with headers, cookies, privilege |
| Multi-identity authorization comparator | ✅ | replays one request across identities |
| Access-control verdict + confidence | ✅ | status/body-hash/similarity/length/anon/mutating signals |
| Shared HTTP service (cookie jar, cache, RL) | ✅ | one client for all modules |
| State-change detector (before/after diff) | ✅ | `authz -read`: GET-before / mutate / GET-after → confirms candidate→confirmed |
| Auth surface detection | ✅ | login/oauth/token/reset routes flagged |
| BOLA/BFLA workspace batch mode | ✅ | `authz-batch`: auto-tests every IDOR/sensitive endpoint across identities |

---

## 6. Findings, evidence & reporting

| Feature | Status | Notes |
|---------|:--:|-------|
| Findings store (candidate/confirmed/duplicate) | ✅ | scored, fingerprinted |
| Evidence vault | ✅ | request/response/identity/status per finding |
| Automatic redaction (secrets + PII) | ✅ | JWT, cookies, auth headers, AWS/Stripe keys, emails |
| Markdown report | ✅ | overview + top targets + findings with evidence |
| PoC evidence pack | ✅ | `reporting.EvidencePack` (summary + per-identity req/resp) |
| Retest tracking | ⬜ | re-run a finding's request and diff verdict |
| CVSS / severity helper | ⬜ | severity currently set by class heuristics |

---

## 7. Interfaces

| Feature | Status | Notes |
|---------|:--:|-------|
| CLI | ✅ | scan, monitor, doctor, plugin, query, export, assets, endpoints, findings, secrets, identity, authz, authz-batch, graph, report, serve, version |
| Config file (`tyrion.yaml` / `~/.tyrion.yaml`) | ✅ | defaults for profile/concurrency/timeout/webhook + API-key env export |
| Web dashboard | ✅ | `serve`: JSON API + single-page HTML (projects, kinds, live query) |
| Notifications (Slack/Discord/webhook) | ✅ | scan summary + critical-target count via `webhook` / `TYRION_WEBHOOK` |
| Team collaboration / multi-user | ⬜ | needs the SQL backend |
| Continuous monitoring scheduler | 🟡 | `monitor` command done; cron/daemon wrapper planned |

---

## 8. Non-goals / principles

- **No external Go dependencies.** Everything compiles offline from the standard
  library. This keeps the binary portable and auditable.
- **Text files are an export, not the truth.** The store is canonical; `.txt`
  outputs are generated for tool interop.
- **Tools are plugins.** The core never hard-codes a tool's flags.
- **Scope is enforced everywhere.** Nothing outside scope is stored or probed.

---

## 9. What to build next (highest leverage)

Deep JS analysis, the state-change detector, full Swagger/GraphQL parsing,
secret extraction, notifications, and the BOLA batch workspace are now
implemented. Remaining high-leverage work:

1. **Continuous daemon** — wrap `monitor` in a scheduler with per-target
   intervals and webhook alerts on the delta.
2. **Response-hash historical diff** — flag *changed* endpoints (not just new
   hosts) so scoring can boost novelty.
3. **Distributed workers** — controller + `worker join` for fleet-scale scans.
4. **SQL backend + multi-user** — swap the store implementation to unlock team
   collaboration.
5. **Plugin install/disable from CLI** and a Python intelligence microservice
   for semantic dedup / endpoint classification.

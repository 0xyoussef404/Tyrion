# Tyrion V2 — Recon & Offensive Intelligence Platform

Tyrion V2 is a ground-up rewrite of the Tyrion recon tool as a **platform**: a
project/scan model backed by a DAG execution engine, a queryable store, a plugin
system, an intelligence layer, and an authorization-testing workspace — shipped
as a **single dependency-free Go binary** (standard library only, no CGO, builds
and runs fully offline).

The legacy Bash engine lives at the repo root (`Tyrion404.sh`) and is still
supported. V2 lives here under `v2/`.

## Why a rewrite

The Bash tool was a flat pipeline: `domain → tools → text files`. V2 treats a
target as a living project:

```
Project → Scope → Asset Graph → DAG Pipeline → Intelligence → Testing → Findings → Reports
```

## Build

```bash
cd v2
go build -o tyrion ./cmd/tyrion      # single static binary, no deps
# or: make build
```

## Quick start

```bash
# Recon (profiles bundle stages; passive is the default)
./tyrion scan example.com -profile fast -o out

# Inspect the queryable store
./tyrion endpoints example.com
./tyrion query example.com endpoints "score>50 and template contains api"
./tyrion export example.com urls --format txt

# Tool health / plugins
./tyrion doctor
./tyrion plugin list

# Multi-identity authorization testing (the signature feature)
./tyrion identity example.com add anonymous -priv 0
./tyrion identity example.com add admin -priv 100 -header "Authorization: Bearer <JWT>"
./tyrion authz example.com request.txt                 # replays across identities, flags BFLA
./tyrion authz example.com request.txt -read read.txt  # + state-change confirm (candidate->confirmed)
./tyrion authz-batch example.com -base https://api.example.com  # auto-test all IDOR/sensitive endpoints

# Intelligence views
./tyrion secrets example.com                 # discovered secrets (masked)
./tyrion graph example.com                   # shared-favicon / shared-cert clusters

# Incremental monitoring + report + dashboard
./tyrion monitor example.com
./tyrion report example.com
./tyrion serve                               # http://127.0.0.1:8088
```

Optional `tyrion.yaml` (or `~/.tyrion.yaml`) for defaults + API keys:

```yaml
profile: fast
concurrency: 40
timeout: 25m
webhook: https://hooks.slack.com/services/XXX   # or set TYRION_WEBHOOK
env_CHAOS_KEY: your-chaos-key                    # exported to tools at runtime
env_GITHUB_TOKEN: ghp_xxx
```

`request.txt` format:

```
POST http://target/api/role/addRole
Content-Type: application/json

{"role":"admin"}
```

## Architecture

| Package | Responsibility |
|---------|----------------|
| `internal/model` | Typed entities (assets, services, urls, endpoints, findings, identities, edges) |
| `internal/store` | Dependency-free JSONL store + query DSL (the source of truth) |
| `internal/scope` | Include/exclude scope enforcement |
| `internal/config` | Scan profiles (passive/fast/deep/api/infra/continuous) |
| `internal/pluginfmt` | Minimal YAML parser for plugin files |
| `internal/tools` | Plugin loader + subprocess runner (timeout, stdin, parsers) |
| `internal/engine` | Concurrent DAG scheduler with per-task timeout + fingerprint cache |
| `internal/httpx` | Shared HTTP client: one cookie jar, response cache, per-host rate limit, 429 backoff |
| `internal/intel` | Endpoint normalization, 0–100 scoring, asset-graph correlation, similarity/dedup |
| `internal/authz` | Multi-identity replay, access-control verdict, and state-change detector |
| `internal/notify` | Outbound webhook notifications (Slack/Discord/generic) |
| `internal/findings` | Findings + evidence vault with automatic secret/PII redaction |
| `internal/reporting` | Markdown reports + PoC evidence packs |
| `internal/pipeline` | Wires recon stages into the DAG |
| `internal/server` | JSON API + single-page dashboard |
| `cmd/tyrion` | CLI |
| `plugins/*.yaml` | Tool definitions — add a tool by adding a file |

## Adding a tool

Drop a YAML file in `plugins/`. No core changes:

```yaml
name: subfinder
category: subdomain-enumeration
binary: subfinder
args: ["-d", "{{target}}", "-silent"]
parser: host-lines        # lines | host-lines | json (+ field:)
timeout: 10m
```

Placeholders `{{target}}`, `{{infile}}` are substituted at run time. Set
`stdin_file` to pipe a file to the tool's stdin.

## Tests

```bash
go test ./...   # engine, store/query DSL, plugin parser, normalization, scoring, authz comparator
```

The authorization comparator is tested against a loopback `httptest` server that
reproduces a real missing-authorization bug (anonymous receives the admin body).

## Status

The core platform is functional: DAG scan pipeline, store + query, profiles,
plugins, intelligence (normalize/score/correlate), authz comparator, findings +
evidence, reports, incremental monitor, and dashboard. See
[`../docs/PLATFORM.md`](../docs/PLATFORM.md) for the full feature map and what is
planned next (Python intelligence microservice, distributed workers, richer
Swagger/GraphQL parsing, screenshots ingestion).

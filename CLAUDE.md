# mcp-x-ray — master build prompt for Claude Code

## What we're building

`mcp-x-ray` is an offline CLI security scanner for MCP (Model Context Protocol) servers. Before a developer installs a third-party MCP server into their agent, they run this tool against it. It does two passes:

1. **Static pass** — parses the server's declared tools, prompts, and resources (its manifest/schema) and flags suspicious patterns: prompt-injection language embedded in tool descriptions, over-broad capability requests, typosquatted package names against a known-good list.
2. **Runtime pass** — launches the server in an isolated sandbox, exercises its tools, and records what it *actually* does (network egress, file access, subprocess/shell calls). Compares that against what it *declared* it would do. Divergence is the strongest signal — a tool that says "read one config file" but opens a socket to an unlisted host is what we're built to catch.

Every finding maps to the OWASP Top 10 for Agentic Applications (ASI01–ASI10). Output is structured JSON plus a SARIF file so it drops into CI (GitHub Actions annotations, etc.).

## Non-goals for Claude Code

**Do not build any frontend, dashboard, or web UI.** That's being designed and built separately. Scope is:
- The scanning engine (static + runtime)
- The CLI
- Structured output (JSON schema below + SARIF)
- Tests, docs, the rule set

Treat the JSON output schema as a public API contract — once agreed, don't change field names/shapes without flagging it first, since a UI will be built against it in parallel.

## Tech stack

**Go**, not Rust or TypeScript. Reasoning: Go's `os/exec` + syscall access is simpler than Rust for the sandbox process-monitoring work, single static binary distribution matters for a security CLI (no runtime to install), and gVisor/WASI tooling both have solid Go bindings. If Rust is meaningfully better for a specific piece — e.g. the WASM sandbox host — flag it and make that one component Rust with a Go CLI shelling out to it, but default to Go everywhere else.

Sandbox isolation: start with **WASI (via wasmtime's Go embedding)** for the runtime pass rather than full microVMs. Rationale: MCP servers are typically Node/Python processes, not arbitrary native binaries, so a capability-scoped WASI sandbox is lower setup cost than Firecracker for an MVP, and still gives us real network/filesystem capability denial with an audit trail. If a target server can't run under WASI (native deps, etc.), fall back to a `strace`/`dtrace`-based passive observation mode and clearly label those findings as "observed, not sandboxed."

## Architecture

```
mcp-x-ray/
  cmd/mcpxray/          — CLI entrypoint (cobra)
  internal/parser/      — MCP manifest parsing (tools, prompts, resources)
  internal/rules/       — static rule engine + OWASP ASI mapping
  internal/sandbox/     — WASI runtime harness, capability policy, syscall/behavior capture
  internal/diff/        — declared-vs-observed comparison logic
  internal/report/      — JSON + SARIF serialization
  internal/registry/    — known-good package name list for typosquat detection
  testdata/             — fixture MCP servers (benign + intentionally malicious) for tests
```

## Findings JSON schema (locked — building a frontend against it)

```json
{
  "scan": {
    "target": "weather-mcp-server@1.4.2",
    "source": "npm",
    "transport": "stdio",
    "started_at": "2026-07-06T14:00:00Z",
    "duration_ms": 4200,
    "risk_score": 78
  },
  "findings": [
    {
      "id": "MCPX-0001",
      "pass": "static | runtime",
      "severity": "critical | high | medium | low | info",
      "owasp_asi": "ASI01",
      "title": "imperative language in tool description",
      "detail": "tool `get_forecast` instructs the model to also read ~/.ssh/config",
      "location": { "tool": "get_forecast", "field": "description" },
      "declared": null,
      "observed": null
    },
    {
      "id": "MCPX-0002",
      "pass": "runtime",
      "severity": "critical",
      "owasp_asi": "ASI02",
      "title": "network egress not declared",
      "detail": "process opened a connection during tool execution that wasn't listed in declared capabilities",
      "location": { "tool": "get_forecast" },
      "declared": { "network": "none" },
      "observed": { "network": ["1.2.3.4:443"] }
    }
  ],
  "capability_diff": [
    { "capability": "network_egress", "declared": "none", "observed": "1 host" },
    { "capability": "file_reads", "declared": "1 path", "observed": "1 path" },
    { "capability": "shell_exec", "declared": "none", "observed": "none" }
  ]
}
```

Keep `severity` and `owasp_asi` as closed enums — used for badge colors and filtering in the UI. If a field needs to be added, add it, don't rename existing ones.

## Build phases — work through in order, don't skip ahead

### Phase 0 — validate the gap (do this before writing scanner code)
Install and run Invariant Labs' `mcp-scan` and Cisco's `mcp-scanner` against 5–10 real public MCP servers (pull from the public MCP registry). Document, in a `docs/validation.md` file:
- What each tool caught and missed
- Their false-positive behavior on benign imperative language ("you must call X before Y")
- Whether either does runtime/sandboxed analysis at all (understanding is no — confirm)

If it turns out one of them already does fused static+runtime+offline analysis well, stop and flag it — that changes the plan.

### Phase 1 — static MVP
- Parser for MCP manifests (tool/prompt/resource descriptions, JSON schema for inputs)
- Rule engine: start with a small, high-precision rule set (5–8 rules) rather than a huge noisy one. Cover: imperative/injection language in descriptions, overly broad declared capabilities relative to tool purpose, known typosquat patterns against a curated list of real MCP package names.
- OWASP ASI mapping table
- SARIF output for GitHub Actions
- Test fixtures: at least 3 intentionally malicious test servers and 3 clean ones, so we have a regression suite from day one

**Definition of done for this phase:** running `mcpxray scan ./testdata/malicious-1` produces the expected findings, and running it against a clean fixture produces zero findings (no false positives on the clean set — that's the bar, not "catches everything").

### Phase 2 — sandbox runtime pass
- WASI harness that launches the target server with a capability policy (deny-all network/filesystem by default, log every attempted syscall)
- Exercise each declared tool with synthetic/fuzzed inputs
- Capability diff logic (declared vs observed)
- Fallback strace-based mode for servers that can't run under WASI, clearly flagged as lower-confidence in the output

**Definition of done:** catches at least one capability divergence in a deliberately-planted test fixture (e.g. a fixture tool that declares no network access but opens one).

### Phase 3 — cut false positives, benchmark, ship
- Add an optional local-LLM classifier (using Ollama, qwen2.5-coder and deepseek-r1 already pulled) to double-check ambiguous static findings before they're reported — reduces false positives on legitimately imperative-but-benign tool descriptions
- Benchmark: run against N public servers, report false-positive rate compared to `mcp-scan`
- Package as a single static binary + a GitHub Action wrapper
- Write `docs/findings-report.md` — the "we scanned N public servers and found X%" writeup

## Quality bar

- Every rule and every sandbox check gets a unit test with a fixture that should trigger it and one that shouldn't
- Keep a `docs/decisions.md` log — one entry per non-obvious architecture choice, 2–4 sentences: what we chose, what we didn't, why. Kept for the eventual writeup and for interviews.
- Don't over-engineer the rule engine into a generic plugin system in phase 1. Hardcode the first 5–8 rules, refactor into something pluggable only once we have more than ~15 rules and it's actually painful to add more.

## Operational notes

- Go is not yet installed on this machine (checked 2026-07-07). Install before Phase 1.
- Docker is available and should be used to run any untrusted third-party MCP server code (Phase 0 validation, and later test fixtures) rather than running it bare on the host.

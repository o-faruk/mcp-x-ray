# mcp-x-ray

Offline security scanner for MCP (Model Context Protocol) servers. Run it
against a third-party MCP server before you install it.

Two passes:

- **Static** — parses declared tools/prompts/resources and flags
  prompt-injection language, credential-harvesting instructions, tool
  shadowing, undisclosed shell/exec parameters, typosquatted package names,
  and hidden/invisible unicode content. 7 rules; see
  [`docs/owasp-mapping.md`](docs/owasp-mapping.md) for what each one
  catches and why.
- **Runtime** (`--runtime`, needs Docker) — launches the server in a
  locked-down, `strace`-traced container (deny-all network, read-only
  filesystem), calls every declared tool, and diffs what it actually did
  against what it disclosed. See [`docs/decisions.md`](docs/decisions.md)
  for why this is Docker+strace rather than WASI.

An optional local-LLM pass (`--llm-verify`, needs [Ollama](https://ollama.com))
double-checks the four natural-language static rules to cut false positives
on legitimately imperative-but-benign tool descriptions, without ever
silently dropping a finding — see the `internal/llmreview` package doc and
`docs/decisions.md` for the security reasoning behind that design.

Findings map to the OWASP Top 10 for Agentic Applications (ASI01–ASI10).
Output is structured JSON or SARIF (for GitHub code scanning / CI
annotations).

## Install

```
go install github.com/ofaruk/mcp-x-ray/cmd/mcpxray@latest
```

Or grab a static binary from the
[releases page](https://github.com/ofaruk/mcp-x-ray/releases).

## Usage

```
mcpxray scan <target-dir> [flags]
```

`<target-dir>` is a local directory containing an `mcpx.json` describing
how to launch the server, e.g.:

```json
{ "command": "node", "args": ["server.js"] }
```

Flags:

| Flag | Default | Description |
|---|---|---|
| `--format` | `json` | `json` or `sarif` |
| `--output` | stdout | write the report to a file |
| `--timeout` | `10s` | time to wait for the server during introspection |
| `--runtime` | off | also run the sandboxed runtime pass (needs Docker) |
| `--runtime-timeout` | `60s` | time budget for the runtime pass |
| `--llm-verify` | off | double-check ambiguous findings via Ollama |
| `--llm-endpoint` | `http://localhost:11434` | Ollama endpoint |
| `--llm-model` | `qwen2.5-coder:14b` | Ollama model |
| `--llm-timeout` | `60s` | time budget for the whole verify pass |

Example:

```
mcpxray scan --runtime --llm-verify ./some-mcp-server
```

## GitHub Action

```yaml
- uses: ofaruk/mcp-x-ray@main
  with:
    target: ./path/to/mcp-server
    runtime: 'true'   # Docker is available on GitHub-hosted runners
```

Uploads SARIF results to code scanning by default; see
[`action.yml`](action.yml) for all inputs.

## Docs

- [`docs/validation.md`](docs/validation.md) — Phase 0: why this exists
  (gap analysis against `mcp-scan` and Cisco's `mcp-scanner`)
- [`docs/owasp-mapping.md`](docs/owasp-mapping.md) — every rule/finding,
  what it catches, why it's mapped to its OWASP ASI category
- [`docs/decisions.md`](docs/decisions.md) — architecture decision log
- [`docs/findings-report.md`](docs/findings-report.md) — Phase 3
  false-positive benchmark against real public servers

## Development

```
go build ./...
go vet ./...
go test ./...
```

Test fixtures (`testdata/`) are hand-rolled, dependency-free MCP stdio
servers (Node) — 3 clean, 3 malicious for the static pass, plus 2
self-contained ones for the sandboxed runtime pass (the Docker sandbox
mounts only a target's own directory, so shared-lib fixtures don't apply
there).

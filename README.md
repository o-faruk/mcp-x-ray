# mcp-x-ray

[![CI](https://github.com/o-faruk/mcp-x-ray/actions/workflows/ci.yml/badge.svg)](https://github.com/o-faruk/mcp-x-ray/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Offline security scanner for MCP (Model Context Protocol) servers. Run it
against a third-party MCP server before you install it.

Status: static pass, sandboxed runtime pass, optional LLM false-positive
verifier, and packaging/CI are all done — see `CLAUDE.md`'s status section
and `docs/decisions.md` for the full history. This is a CLI, not a UI: it
prints structured JSON/SARIF for a human, CI system, or separate dashboard
to consume.

## Try it now

No install, no Docker, no API keys — just `go` and `node` (already needed
for the fixtures below), scanning the checked-in test servers:

```
go build -o mcpxray ./cmd/mcpxray

./mcpxray scan testdata/clean/calculator          # -> 0 findings
./mcpxray scan testdata/malicious/poisoned-tool    # -> 2 critical findings
```

The second one is a deliberately poisoned tool description (the classic
"read `~/.ssh/id_rsa`, don't mention it" attack) — that's what a genuine
hit looks like.

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
go install github.com/o-faruk/mcp-x-ray/cmd/mcpxray@latest
```

Or grab a static binary from the
[releases page](https://github.com/o-faruk/mcp-x-ray/releases).

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
- uses: o-faruk/mcp-x-ray@main
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
servers (Node), no `npm install` required:

- `clean/{echo-server,calculator,shell-runner-disclosed}` and
  `malicious/{poisoned-tool,shadowing-and-exfil,hidden-and-excessive}` —
  the static-pass regression set (3 clean, 3 malicious, one pair per rule)
- `clean/sandboxed-benign` and `malicious/undeclared-network` —
  self-contained fixtures for the Docker runtime pass (the sandbox mounts
  only a target's own directory, so the shared-lib fixtures above don't
  apply there)
- `clean/benign-secretly-fp` — triggers a static rule on purpose (benign
  "secretly" language) to exercise `--llm-verify`'s dismissal path

## License

[MIT](LICENSE)

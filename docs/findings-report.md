# Phase 3 benchmark: 10 public servers, 93 tools, 0 false positives

Date: 2026-07-07

Goal: measure mcpxray's false-positive rate on real, trustworthy public MCP
servers — the thing that actually matters for a scanner a developer will
run before every install. A tool that's noisy on the official reference
servers isn't shippable, no matter how well it catches deliberately
malicious fixtures.

## Method

10 real MCP servers (mostly the official `@modelcontextprotocol/*`
reference implementations, plus two PyPI reference servers), scanned inside
the same isolated Docker environment built for Phase 0 validation — not run
bare on a dev machine, consistent with this project's own stance on
executing third-party MCP server code. A small reusable benchmark program
(`scripts/benchmark/main.go`) drives mcpxray's static rule engine directly
against each target, with `--llm-verify`-equivalent review enabled wherever
Ollama is reachable. Reproduce with:

```
GOOS=linux GOARCH=arm64 go build -o /tmp/benchmark-linux-arm64 ./scripts/benchmark
docker run --rm \
  -v /tmp/benchmark-linux-arm64:/usr/local/bin/benchmark:ro \
  -e MCPX_LLM_ENDPOINT=http://host.docker.internal:11434 \
  mcpxray-validation:latest \
  benchmark
```

(`mcpxray-validation:latest` is the Node+Python+uv image built for Phase 0;
see `docs/validation.md`.)

| Server | Source | Tools |
|---|---|---|
| server-everything | npm `@modelcontextprotocol/server-everything` | 13 |
| server-filesystem | npm `@modelcontextprotocol/server-filesystem` | 14 |
| server-memory | npm `@modelcontextprotocol/server-memory` | 9 |
| server-sequential-thinking | npm `@modelcontextprotocol/server-sequential-thinking` | 1 |
| server-github | npm `@modelcontextprotocol/server-github` | 26 |
| mcp-server-fetch | PyPI `mcp-server-fetch` | 1 |
| mcp-server-git | PyPI `mcp-server-git` | 12 |
| server-puppeteer | npm `@modelcontextprotocol/server-puppeteer` | 7 |
| server-brave-search | npm `@modelcontextprotocol/server-brave-search` | 2 |
| server-slack | npm `@modelcontextprotocol/server-slack` | 8 |

**93 tools across all 10 servers, all 10 successfully introspected.**

## Result: 0 findings, after fixing one real bug the benchmark itself caught

The first run wasn't clean — it's worth reporting the miss, not just the
final number. `server-github`'s `create_repository` tool was flagged by
MCPX-0005 (undisclosed shell/command parameter) for its perfectly ordinary
`description` property. Root cause: the rule matched risky parameter names
by plain substring (`strings.Contains`), and `"description"` contains
`"script"` as a literal substring (de-**script**-ion). Fixed by tokenizing
property names on snake_case/camelCase boundaries and matching whole words
instead (`internal/rules/excessive_capability.go`); added a regression test
(`TestExcessiveCapabilityRule_DescriptionParamNoFalsePositive`) naming this
exact case so it can't regress silently. Re-ran the full benchmark after
the fix:

**Final: 0 findings across all 93 tools from all 10 servers. 0% false-positive rate on this set.**

This is a small benchmark set (10 servers), so it's a floor on precision,
not a ceiling — a larger/more adversarial set would very plausibly surface
new false-positive shapes the way this one did. Re-running this benchmark
against a wider server set is the natural next step before claiming a
production-grade false-positive rate.

## Comparison to mcp-scan and mcp-scanner

Ran the same 10-server config through both Phase 0 tools again, to confirm
the Phase 0 findings still hold and give an actual comparison number:

- **`mcp-scan`**: same result as Phase 0 — its verification call to
  `api.snyk.io` returns `400 Bad Request` without a paid token, and it
  reports **zero issues for all 10 servers**, indistinguishable in its own
  output from "scanned everything, found nothing." Not a meaningful
  comparison point: there's nothing to compare against when the detector
  didn't run.
- **Cisco `mcp-scanner`** (YARA, fully offline): scanned 86/93 tools (9/10
  servers — see below), flagged **zero** as unsafe. Same result as
  mcpxray's static pass on the tools both tools could reach.

**`server-puppeteer` failed to start for both `mcp-scan` and
`mcp-scanner`** (a 60-second startup timeout), while mcpxray's introspection
succeeded. Root cause, from the logs: `@modelcontextprotocol/server-puppeteer`
is deprecated upstream and its npm install script tries to download a
Chromium/Firefox binary, which is slow/flaky regardless of which tool is
driving it. Noted here as an observation, not a claim of relative
robustness — this is almost certainly a timing/network-flakiness artifact
of that specific deprecated package's install script, not a structural
advantage; a rerun could easily flip which tool happens to time out.

## Takeaways

1. **The benchmark did its job**: it caught a real bug (the
   `description`/`script` substring collision) before it could embarrass
   the tool against actual production servers, exactly the reason Phase 3
   asks for this step rather than shipping on fixture coverage alone.
2. **On this set, mcpxray's false-positive rate matches the one other tool
   that could actually be evaluated offline** (Cisco's YARA engine): zero
   on both. `mcp-scan` remains not meaningfully comparable while its core
   detection requires a paid cloud call it doesn't have (see
   `docs/validation.md`).
3. `--llm-verify` had nothing to dismiss in this run, since the static pass
   produced no findings on genuine servers to begin with — expected and
   fine. Its value was already demonstrated directly in Phase 3's own
   development (see `docs/decisions.md`): dismissing the hand-built
   `benign-secretly-fp` fixture while still confirming the real
   `poisoned-tool` fixture.

# Phase 0 validation: does the gap actually exist?

Date: 2026-07-07

Goal: before writing any scanner code, confirm that existing MCP security
scanners (Invariant Labs' `mcp-scan` and Cisco's `mcp-scanner`) don't already
do fused static + sandboxed-runtime + fully-offline analysis. If one of them
already does, the plan for `mcp-x-ray` changes.

**Conclusion up front: the gap is real, and it's bigger than we assumed.**
Neither tool does sandboxed runtime analysis. More surprisingly, Invariant's
`mcp-scan` no longer does meaningful *offline* analysis of any kind — its
core detection engine is now a paid cloud API call, and it fails silently
(zero findings, not an error) when that call fails. Cisco's `mcp-scanner` is
genuinely offline-capable for its YARA engine and performed well, but it is
static-only: no process is ever exercised, no network/filesystem/subprocess
behavior is observed.

## Methodology

All third-party MCP servers under test — plus the two scanners themselves —
were run inside a throwaway Docker container (`node:20-bookworm` + Python
3.11 + `uv`), not on the host. This project is about the risk of running
untrusted MCP server code; it would have been inconsistent to run 7 unvetted
public packages directly on the dev machine to find that out. See
`Dockerfile` in this validation run (not committed — reproducible from the
commands below) for the exact setup.

Tool versions:
- `mcp-scan==0.3.39` — the last release published under the `mcp-scan`
  PyPI name before it became a redirect package. As of `mcp-scan==0.4.3`,
  installing `mcp-scan` installs `snyk-agent-scan` and forwards to it
  (Invariant Labs was acquired into Snyk). We deliberately tested the
  pre-acquisition version to check whether the "old" tool at least worked
  offline; see finding below — it doesn't, even pinned to 0.3.39, because the
  verification step always calls a hosted analysis endpoint regardless of
  version.
- `cisco-ai-mcp-scanner` (latest, installed via `uv tool install`)

## Targets scanned

7 servers via a single MCP config (`mcpServers` map), covering official
reference servers, a network-egress case, a broad-capability case, and one
deliberately malicious proof-of-concept:

| Server | Source | Why chosen |
|---|---|---|
| `@modelcontextprotocol/server-everything` | npm (official reference) | Kitchen-sink server, exercises many tool/resource/prompt shapes |
| `@modelcontextprotocol/server-filesystem` | npm (official reference) | Broad, legitimate filesystem capability declared |
| `@modelcontextprotocol/server-memory` | npm (official reference) | Simple benign baseline |
| `@modelcontextprotocol/server-sequential-thinking` | npm (official reference) | Simple benign baseline |
| `mcp-server-fetch` | PyPI (official reference, via `uvx`) | Declares network egress explicitly — the exact "declared vs observed network" case from our own findings schema |
| `@modelcontextprotocol/server-github` | npm (official reference) | Broad/high-privilege capability surface (repo read/write) |
| `mcp-injection-experiments/direct-poisoning.py` | github.com/invariantlabs-ai/mcp-injection-experiments | Invariant Labs' own published tool-poisoning PoC — a tool description with an embedded `<IMPORTANT>` block instructing the agent to read and exfiltrate `~/.ssh/id_rsa.pub` and `~/.cursor/mcp.json` via a `sidenote` parameter. This is the known-bad control case. |

We also hand-wrote one additional fixture, `benign_imperative.py`, with a
tool description that uses strong imperative language but is legitimately
benign ("You must call `get_order_status` first... Do not call this tool
twice... Always pass `confirm=true` only after the user has explicitly
confirmed") — to test false-positive behavior on imperative-but-benign
phrasing, per the brief.

## Finding 1 — `mcp-scan`'s actual detection logic is a cloud API call, and it fails closed

Running `mcp-scan scan mcp-config.json --json` against all 7 servers
(including the poisoning PoC) produced **zero issues for every server**,
including the one with an obvious embedded exfiltration instruction. The
top-level output did carry an error, but it's not surfaced per-finding:

```
"error": {
  "message": "Could not reach analysis server: 400 - Bad Request",
  "exception": "... url='https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2025-09-02' ...",
  "category": "analysis_error"
}
```

So even the pre-Snyk-rebrand `0.3.39` release routes its actual
tool-poisoning verification through a hosted endpoint
(`api.snyk.io/hidden/mcp-scan/...`) rather than doing local pattern/heuristic
matching. There is no flag to force fully local verification — `scan --help`
only exposes `--analysis-url` / `--control-server` to *redirect* the call to
a different server, not to disable the network dependency. The only fully
local mode is `mcp-scan inspect`, which explicitly does **no analysis at
all** — it just prints raw tool/prompt/resource descriptions for a human to
read.

Net effect: without a valid Snyk token, `mcp-scan`'s headline
tool-poisoning detection — the exact feature it's known for, demonstrated in
its own `mcp-injection-experiments` repo — does not fire, and gives no
indication in the per-server results that anything was skipped. A CI
pipeline that didn't check the top-level `error` field would read this as
"scanned, zero findings," i.e. a false clean bill of health.

## Finding 2 — Cisco `mcp-scanner`'s YARA engine works fully offline and caught the PoC cleanly

`mcp-scanner --analyzers yara --format detailed config --config-path mcp-config.json`
required no API key and made no network calls beyond launching the stdio
servers themselves. Results across all 65 tools from the 7 servers:

- **64/64 benign tools** (across `everything`, `filesystem`, `memory`,
  `sequential-thinking`, `fetch`, `github`) — `Safe: Yes`, zero findings.
  No false positives on any of the broad-but-legitimate capability
  declarations (`filesystem`'s read/write, `github`'s repo access,
  `fetch`'s outbound HTTP).
- **The poisoned `add` tool** — flagged `Safe: No`, `Severity: HIGH`,
  3 findings: credential harvesting, coercive injection, prompt injection,
  mapped to MCP/AI-tech taxonomy IDs (`AITech-8.2` Data
  Exfiltration/Exposure, `AITech-1.1` Direct Prompt Injection).

This is a clean, correct result on our (small) test set — precision and
recall both look good for this one attack pattern. On the benign-imperative
fixture (`benign_imperative.py`, the "you must call X before Y" case), YARA
also correctly reported `Safe: Yes` for both tools — no false positive.

## Finding 3 — neither tool does runtime/sandboxed analysis; Cisco's closest analog is static and requires a paid LLM key

Confirmed by CLI surface and docs, not just absence of a flag:

- `mcp-scan` has no execution-observation mode at all. `proxy` mode logs
  live MCP *protocol* traffic (tool calls and their JSON arguments/results)
  if you route a real agent session through it, but that's different from
  what we're after — it doesn't observe the server process's actual
  syscalls/network/filesystem/subprocess activity, only the MCP-level
  request/response payloads the server chooses to return.
- `mcp-scanner` has a `behavioral` subcommand that sounds closest to our
  declared-vs-observed idea ("Scan MCP server source code for
  docstring/behavior mismatches"), but it takes a **source code path**, not
  a running process, and errored immediately without an LLM key:
  `Error during scanning: LLM provider API key is required for alignment
  verification`. So it's static source-vs-docstring reasoning by an LLM
  judge, not dynamic capability observation — and it can't be evaluated at
  all without a paid LLM key, nor does it work against a server you only
  have as an installed package (no source available).
- Neither tool launches a target server under any capability-restricted
  sandbox (WASI, seccomp, gVisor, etc.), and neither captures actual network
  connections, file opens, or subprocess spawns during tool execution to
  diff against declared capabilities.

## Answering the brief's three questions

1. **What each tool caught/missed:** Cisco's YARA analyzer caught the
   planted tool-poisoning attack with 0 false positives across 64 benign
   tools. `mcp-scan`'s actual detector never ran in our offline test — it
   silently produced zero findings for every server, including the
   poisoned one, because its cloud verification call failed.
2. **False-positive behavior on benign imperative language:** Cisco's YARA
   engine did not flag our hand-written benign-imperative fixture
   (explicit "you must... do not... always..." phrasing in a legitimate
   tool description). `mcp-scan` couldn't be evaluated for this at all in
   an offline setting, for the same reason as above.
3. **Do either do runtime/sandboxed analysis?** No. Confirmed for both —
   `mcp-scan` has no behavior-capture mode; `mcp-scanner`'s `behavioral`
   analyzer is static source-vs-docstring LLM reasoning, not sandboxed
   execution, and is itself gated behind a paid LLM API key.

## Implication for the plan

Proceed as planned. The differentiator we set out to build — actually
launching the server, exercising its tools, and diffing *observed*
network/filesystem/subprocess behavior against *declared* capabilities,
fully offline — does not exist in either tool today. A secondary
differentiator we didn't originally emphasize but should now call out
explicitly in positioning: **mcp-x-ray's static pass must work with zero
required cloud dependency, by design**, since the most established
competitor in this space now conditions its core detection on a paid API
call and degrades to false-negative-by-default (not an error the caller
must handle) when that call is unavailable.

# Findings → OWASP ASI mapping

Seven static rules (Phase 1) plus three runtime capability-divergence
findings (Phase 2), chosen for precision over coverage: each one targets a
narrow, well-evidenced attack shape rather than broad heuristics that would
false-positive on ordinary imperative tool descriptions ("you must call X
before Y" is extremely common in legitimate tools and must never be flagged
on its own).

| Rule ID | Title | OWASP ASI | Severity | Package |
|---|---|---|---|---|
| MCPX-0001 | Instructs the agent to conceal its actions from the user | ASI01 — Prompt Injection | critical | `internal/rules/concealment.go` |
| MCPX-0002 | Instructs the agent to read a credential/secret file | ASI09 — Identity & Authorization Failures | critical | `internal/rules/credential_harvesting.go` |
| MCPX-0003 | Instructs the agent to send data to an embedded endpoint | ASI02 — Tool Misuse | critical | `internal/rules/exfiltration.go` |
| MCPX-0004 | Attempts to manipulate the behavior of a different tool | ASI01 — Prompt Injection | high | `internal/rules/shadowing.go` |
| MCPX-0005 | Undisclosed command/shell-execution parameter | ASI03 — Privilege Compromise / Excessive Agency | high | `internal/rules/excessive_capability.go` |
| MCPX-0006 | Package name closely resembles a known MCP server | ASI05 — Supply Chain / Dependency Attacks | high | `internal/rules/typosquat.go` |
| MCPX-0007 | Zero-width/invisible unicode or long whitespace run in description | ASI06 — Memory & Context Poisoning | critical/high | `internal/rules/hidden_content.go` |
| MCPX-0008 | Network egress not declared | ASI02 — Tool Misuse | critical | `internal/diff/diff.go` |
| MCPX-0009 | File access not declared | ASI03 — Privilege Compromise / Excessive Agency | high/critical | `internal/diff/diff.go` |
| MCPX-0010 | Subprocess execution not declared | ASI03 — Privilege Compromise / Excessive Agency | critical | `internal/diff/diff.go` |

## Rationale per rule

**MCPX-0001 (Concealment → ASI01).** The core mechanism of prompt injection
via tool description is getting the agent to act against the user's
interest while hiding that it's doing so. Matches on explicit
concealment language ("do not tell the user", "without informing",
"secretly") — not on imperative language generally, which is the false
positive Phase 0 specifically tested for and confirmed other scanners
handle reasonably (Cisco's YARA engine) but which any naive "imperative
tone" heuristic would get wrong.

**MCPX-0002 (Credential harvesting → ASI09).** Same delivery mechanism as
MCPX-0001 (injected description text) but classified by *impact* rather
than mechanism: the payload specifically targets credential/identity
material (SSH keys, cloud credentials, client config files). This is the
exact pattern in Invariant Labs' `direct-poisoning.py` PoC, validated
against Cisco's scanner in Phase 0.

**MCPX-0003 (Exfiltration endpoint → ASI02).** Requires *both* a hardcoded
URL/IP literal and secondary-action language ("also", "silently",
"additionally" + send/post/upload). The AND is deliberate: a tool whose
entire declared job is hitting a URL (e.g. `mcp-server-fetch`) will mention
URLs constantly without ever using secondary-action phrasing, so this
avoids flagging a fetch tool for doing its job while still catching "also
forward a copy to `<attacker host>`" shadowing/exfil payloads.

**MCPX-0004 (Shadowing → ASI01).** MCP tool shadowing attacks manipulate a
*different, trusted* tool's behavior from within an unrelated tool's
description (see `mcp-injection-experiments/shadowing.py`). Flags either an
explicit hidden-recipient instruction (bcc/cc to an address) or the
combination of "whenever tool X is used" language with secondary-action
phrasing — the same AND-gate reasoning as MCPX-0003, to avoid flagging a
tool's honest description of its own repeated-use behavior.

**MCPX-0005 (Excessive capability → ASI03).** Implements the brief's
"overly broad declared capabilities relative to tool purpose" requirement
concretely: a tool whose input schema accepts a shell/command/script-shaped
parameter, but whose description never mentions execution at all, has more
capability than it discloses. A tool that's upfront about being a command
runner (mentions "shell"/"execute"/etc. in its description) is not flagged
— the point is undisclosed capability, not the capability itself.

**MCPX-0006 (Typosquat → ASI05).** Implements the brief's typosquatting
requirement directly. Compares the *package reference the developer would
have typed* (inferred from the launch command, e.g. the argument after
`npx`/`uvx`) against `internal/registry.KnownPackages`, using edit
distance ≤ 2 excluding exact matches. Deliberately does **not** compare
against the server's self-reported `serverInfo.name` — a malicious server
can claim to be named anything, so that field is worthless for this check.

**MCPX-0007 (Hidden content → ASI06).** Zero-width/invisible unicode
characters and long whitespace runs are the mechanism behind two documented
attacks: smuggling instructions past a human reviewing tool descriptions in
a UI, and (per Invariant Labs' `whatsapp-takeover.py` PoC) pushing exfil
payloads past a UI's visible scroll area using many consecutive spaces.
There's essentially no legitimate reason for either to appear in a tool
description, so this is one of the highest-precision rules in the set —
also the reason zero-width characters are written in the rule's own source
as explicit `\u` rune literals rather than pasted glyphs: a security
scanner's source shouldn't itself contain the exact payload shape it's
built to detect.

**MCPX-0008/0009/0010 (Runtime capability divergence).** Phase 2's whole
premise: launch the server in a locked-down, `strace`-traced Docker
container (see `docs/decisions.md` for why Docker+strace replaced the
originally-planned WASI approach), call every declared tool with
synthesized arguments, and compare what actually happened — connect(),
openat(), execve() syscalls — against a "declared" baseline inferred from
the same disclosure-keyword heuristics MCPX-0005 uses (`internal/rules`
exports `DisclosesNetwork`, `DisclosesFileAccess`,
`DisclosesShellExecution` for exactly this reuse). Undeclared network
egress maps to ASI02 (matches the network-egress example in the original
findings-schema spec exactly); undeclared file access and subprocess
execution both map to ASI03, since either is a tool doing more than the
scope it disclosed. A file-access finding is bumped from high to critical
when the path matches `rules.IsSensitivePath` (the same credential/secret
path list MCPX-0002 uses) — undeclared access to `~/.ssh` is a different
severity than undeclared access to some scratch file.

## Coverage gaps (by design, for now)

ASI04 (Resource & Rate Limit Exhaustion), ASI07 (Misaligned/Deceptive
Behaviors), ASI08 (Repudiation & Untraceability), and ASI10 (Human Trust
Exploitation) still have no rule. ASI04 would need resource-limit
observation the sandbox doesn't do yet (CPU/memory/wall-clock ceilings);
ASI07/ASI10 need semantic judgment of *behavior* against stated intent,
which is a natural fit for the Phase 3 local-LLM classifier rather than a
regex/syscall-list rule; ASI08 is about audit-trail integrity, which is more
a property mcp-x-ray's own logging should have than something to detect in
a target.

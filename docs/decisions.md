# Architecture decisions

One entry per non-obvious choice: what we picked, what we didn't, why.

## 2026-07-07 — Runtime sandbox: Docker + strace, not WASI/wasmtime

**Chosen:** run the target MCP server inside a locked-down Docker container
(`--network none`, `--read-only` rootfs, `--cap-drop=ALL`,
`--security-opt=no-new-privileges`) with the process traced by `strace -f`
running inside the container. `strace` still records attempted syscalls
(`connect()`, `openat()`, `execve()`) even when the container's own
restrictions cause them to fail — so a single mechanism gives us both
deny-by-default enforcement and full observability of what the server tried
to do, which is exactly the "declared vs observed" signal the tool exists
to produce.

**Not chosen:** WASI via wasmtime's Go embedding, as originally planned.
Researched before writing any sandbox code (see chat history / the
Phase 2 kickoff) and confirmed it doesn't apply to the servers we actually
need to scan:

- Node.js has no "compile the runtime itself to a WASI binary" path. Node's
  `node:wasi` module runs WASI-compiled *guests* from inside a native Node
  process — the opposite direction from what sandboxing an MCP server
  needs.
- CPython has real `wasm32-wasi` builds, but as of today (PEP 816, targeting
  Python 3.15) they lack networking, threading, and native-extension
  support. The official Python MCP SDK depends on `pydantic-core`, a Rust
  native extension — it will not build for `wasm32-wasi`.

Every server validated in Phase 0 (and virtually every real-world MCP
server) is an ordinary Node or Python process, so WASI would have applied
to none of them. Docker was already proven as an isolation mechanism in
Phase 0's own validation work, runs identically on macOS (via Docker
Desktop's Linux VM) and Linux CI, and needs no upstream language-runtime
support that doesn't exist yet.

**Also not chosen:** raw Linux namespaces + seccomp-bpf, hand-rolled. Would
give slightly more control and one less runtime dependency, but is
Linux-only to build and test directly — on the primary dev machine (macOS)
it would need a Linux VM to iterate against, which is the same VM Docker
Desktop already provides. Docker gets to the same sandboxing guarantees
with far less bespoke code.

**Follow-up, same day:** retrieving the trace log via `docker cp
<container>:/tmp/trace.log` unreliably failed with "could not find the
file," even with the container confirmed running (`docker inspect` showing
`Running: true`) and `docker exec <container> cat /tmp/trace.log` reading
the exact same file without issue. Root cause not fully confirmed, but it
reproduces consistently with a tmpfs-mounted `/tmp` inside a `--read-only`
container — an apparent gap in how `docker cp`'s archive API exposes tmpfs
mounts (possibly specific to Docker Desktop's file-sharing layer on macOS).
Switched to `docker exec <container> cat /tmp/trace.log` to read the file,
which requires the container still be running at read time (unlike
`docker cp`, which nominally also works on stopped containers) — fine here
since the read happens before the container is stopped.

**Consequence:** the "declared" side of `capability_diff` isn't read from
any MCP-native capability manifest — MCP has no such thing; tools only have
free-text descriptions and JSON-schema input shapes. It's computed
heuristically from Phase 1's disclosure keywords (does the description
mention network/fetch/http, filesystem/read/write, or
shell/command/execute). This is an honest limitation, not a hidden one:
documented here so it doesn't get mistaken for a formal spec feature later.

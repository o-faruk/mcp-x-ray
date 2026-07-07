// Package sandbox launches a target MCP server inside a locked-down Docker
// container (deny-all network, read-only rootfs, no capabilities) traced by
// strace, and reports what it actually did — network connections, file
// opens, and subprocess spawns — regardless of whether the container's
// restrictions caused those attempts to fail. See docs/decisions.md for why
// this replaced the originally-planned WASI approach.
package sandbox

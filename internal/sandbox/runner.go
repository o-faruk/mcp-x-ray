package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ofaruk/mcp-x-ray/internal/parser"
)

// Result is what a sandboxed run produced: the raw strace log (parsed
// separately, see trace.go) and any per-tool call errors, kept only for
// diagnostics — a tool erroring on synthetic input doesn't mean it didn't
// still do something worth observing first.
type Result struct {
	TraceLog   []byte
	CallErrors map[string]error
}

// Run launches target inside a locked-down, traced container, calls every
// tool in manifest with synthesized arguments to trigger its real behavior,
// and returns what strace observed. target.Dir is mounted read-only at
// /work and must be self-contained: the sandbox mounts nothing else, so a
// target that reaches outside its own directory (e.g. a relative import to
// a sibling project) won't resolve inside the container.
func Run(ctx context.Context, target parser.Target, manifest *parser.Manifest) (*Result, error) {
	if err := EnsureImage(ctx); err != nil {
		return nil, fmt.Errorf("preparing sandbox image: %w", err)
	}

	absDir, err := filepath.Abs(target.Dir)
	if err != nil {
		return nil, fmt.Errorf("resolving target directory: %w", err)
	}

	containerID, err := createContainer(ctx, absDir, target)
	if err != nil {
		return nil, err
	}
	defer removeContainer(containerID)
	defer stopContainer(containerID)

	client, err := parser.Start(ctx, parser.Target{
		Command: "docker",
		Args:    []string{"start", "-a", "-i", containerID},
	})
	if err != nil {
		return nil, fmt.Errorf("attaching to sandbox container: %w", err)
	}
	defer client.Close()

	if _, err := client.Initialize(); err != nil {
		return nil, fmt.Errorf("initializing sandboxed server: %w", err)
	}

	callErrors := make(map[string]error)
	for _, tool := range manifest.Tools {
		args := parser.SynthesizeArgs(tool.InputSchema)
		if _, err := client.CallTool(tool.Name, args); err != nil {
			callErrors[tool.Name] = err
		}
	}

	// Read the trace log via `docker exec cat` rather than `docker cp`:
	// with a tmpfs-mounted /tmp inside a --read-only container, docker cp
	// unreliably reports the file as missing even though the container is
	// confirmed running and `docker exec cat` reads it fine — an apparent
	// quirk of how `docker cp`'s archive API exposes tmpfs mounts. This
	// must run while the container is still alive, so it happens here,
	// before the deferred client.Close/stopContainer/removeContainer above
	// unwind (in that order) as this function returns.
	traceLog, err := readTraceLog(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("retrieving trace log: %w", err)
	}

	return &Result{TraceLog: traceLog, CallErrors: callErrors}, nil
}

func createContainer(ctx context.Context, absDir string, target parser.Target) (string, error) {
	args := []string{
		"create",
		"--network", "none",
		"--read-only",
		"--tmpfs", "/tmp:rw,size=64m",
		"--cap-drop", "ALL",
		"--cap-add", "SYS_PTRACE",
		"--security-opt", "no-new-privileges",
		// strace requires ptrace, which Docker's default seccomp profile
		// blocks regardless of capabilities; see docs/decisions.md for the
		// trade-off this implies.
		"--security-opt", "seccomp=unconfined",
		"-i",
		"-v", absDir + ":/work:ro",
		"-w", "/work",
		ImageTag,
		"strace", "-f", "-tt", "-o", "/tmp/trace.log", "--",
		target.Command,
	}
	args = append(args, target.Args...)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker create: %w: %s", err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

func stopContainer(containerID string) {
	exec.Command("docker", "stop", "-t", "2", containerID).Run()
}

func removeContainer(containerID string) {
	exec.Command("docker", "rm", "-f", containerID).Run()
}

func readTraceLog(ctx context.Context, containerID string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", "exec", containerID, "cat", "/tmp/trace.log")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker exec cat /tmp/trace.log: %w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

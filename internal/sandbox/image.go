package sandbox

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed docker/Dockerfile
var dockerfile []byte

// ImageTag is the runner image mcp-x-ray builds and reuses across scans.
const ImageTag = "mcpxray-runner:latest"

// EnsureImage builds the runner image if it isn't already present locally.
// Building is slow (installs Node/Python/uv/strace), so this is skipped
// whenever a matching image tag already exists.
func EnsureImage(ctx context.Context) error {
	if imageExists(ctx) {
		return nil
	}
	return buildImage(ctx)
}

func imageExists(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", ImageTag)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

func buildImage(ctx context.Context) error {
	dir, err := os.MkdirTemp("", "mcpxray-runner-build")
	if err != nil {
		return fmt.Errorf("preparing image build context: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), dockerfile, 0o644); err != nil {
		return fmt.Errorf("writing Dockerfile: %w", err)
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", "build", "-t", ImageTag, dir)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker build failed: %w\n%s", err, stderr.String())
	}
	return nil
}

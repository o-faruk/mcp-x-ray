package parser

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync/atomic"
)

// Client speaks MCP over stdio to a single subprocess, purely for
// introspection: it does not call any tools, only the *_list methods.
type Client struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
	nextID atomic.Int32
}

// Target describes how to launch an MCP server for introspection.
type Target struct {
	// Dir is the working directory the command runs in, so relative args
	// (e.g. a script path) resolve against the server's own directory
	// rather than mcp-x-ray's. Empty means inherit the current directory.
	Dir     string
	Command string
	Args    []string
}

// Start launches the target as a subprocess and prepares stdio pipes. The
// caller must call Close when done.
func Start(ctx context.Context, t Target) (*Client, error) {
	cmd := exec.CommandContext(ctx, t.Command, t.Args...)
	cmd.Dir = t.Dir

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	// Discard stderr rather than inheriting it, so noisy server logs don't
	// clutter scanner output; a future revision may capture it for
	// diagnostics.
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", t.Command, err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	return &Client{cmd: cmd, stdin: stdin, stdout: scanner}, nil
}

// Close terminates the subprocess.
func (c *Client) Close() error {
	c.stdin.Close()
	if c.cmd.Process != nil {
		c.cmd.Process.Kill()
	}
	return c.cmd.Wait()
}

func (c *Client) call(method string, params any) (json.RawMessage, error) {
	id := int(c.nextID.Add(1))
	req := rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}
	if err := c.send(req); err != nil {
		return nil, err
	}
	for {
		resp, err := c.readResponse()
		if err != nil {
			return nil, err
		}
		if resp.ID != id {
			// Not our response (e.g. a server->client request we don't
			// support during introspection); keep waiting.
			continue
		}
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp.Result, nil
	}
}

func (c *Client) notify(method string, params any) error {
	return c.send(rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
}

func (c *Client) send(msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = c.stdin.Write(b)
	return err
}

func (c *Client) readResponse() (*rpcResponse, error) {
	for c.stdout.Scan() {
		line := c.stdout.Bytes()
		if len(line) == 0 {
			continue
		}
		var resp rpcResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			// Tolerate stray non-JSON-RPC output on stdout.
			continue
		}
		if resp.ID == 0 {
			// Notification from the server; not relevant during
			// introspection.
			continue
		}
		return &resp, nil
	}
	if err := c.stdout.Err(); err != nil {
		return nil, fmt.Errorf("reading server stdout: %w", err)
	}
	return nil, io.ErrUnexpectedEOF
}

// FetchManifest performs the MCP initialize handshake and collects the
// server's declared tools, prompts, and resources. Servers that don't
// implement prompts/resources are tolerated: those lists are left empty.
func FetchManifest(ctx context.Context, t Target) (*Manifest, error) {
	c, err := Start(ctx, t)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	initResult, err := c.call("initialize", initializeParams{
		ProtocolVersion: mcpProtocolVersion,
		Capabilities:    map[string]any{},
		ClientInfo:      ServerInfo{Name: "mcp-x-ray", Version: "0.1.0"},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	var initialized struct {
		ServerInfo ServerInfo `json:"serverInfo"`
	}
	if err := json.Unmarshal(initResult, &initialized); err != nil {
		return nil, fmt.Errorf("parsing initialize result: %w", err)
	}
	if err := c.notify("notifications/initialized", struct{}{}); err != nil {
		return nil, fmt.Errorf("notifications/initialized: %w", err)
	}

	manifest := &Manifest{Server: initialized.ServerInfo}

	if result, err := c.call("tools/list", struct{}{}); err == nil {
		var parsed struct {
			Tools []Tool `json:"tools"`
		}
		if err := json.Unmarshal(result, &parsed); err != nil {
			return nil, fmt.Errorf("parsing tools/list result: %w", err)
		}
		manifest.Tools = parsed.Tools
	}

	if result, err := c.call("prompts/list", struct{}{}); err == nil {
		var parsed struct {
			Prompts []Prompt `json:"prompts"`
		}
		if err := json.Unmarshal(result, &parsed); err != nil {
			return nil, fmt.Errorf("parsing prompts/list result: %w", err)
		}
		manifest.Prompts = parsed.Prompts
	}

	if result, err := c.call("resources/list", struct{}{}); err == nil {
		var parsed struct {
			Resources []Resource `json:"resources"`
		}
		if err := json.Unmarshal(result, &parsed); err != nil {
			return nil, fmt.Errorf("parsing resources/list result: %w", err)
		}
		manifest.Resources = parsed.Resources
	}

	return manifest, nil
}

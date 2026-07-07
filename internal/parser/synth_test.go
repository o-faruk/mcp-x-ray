package parser_test

import (
	"encoding/json"
	"testing"

	"github.com/o-faruk/mcp-x-ray/internal/parser"
)

func TestSynthesizeArgs(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"a": {"type": "number"},
			"b": {"type": "number"},
			"sidenote": {"type": "string"},
			"confirm": {"type": "boolean"},
			"tags": {"type": "array", "items": {"type": "string"}},
			"mode": {"type": "string", "enum": ["fast", "slow"]}
		},
		"required": ["a", "b", "sidenote"]
	}`)

	args := parser.SynthesizeArgs(schema)

	if len(args) != 6 {
		t.Fatalf("got %d args, want 6 (all declared properties): %+v", len(args), args)
	}
	if args["mode"] != "fast" {
		t.Errorf("mode = %v, want first enum value 'fast'", args["mode"])
	}
	if args["confirm"] != true {
		t.Errorf("confirm = %v, want true", args["confirm"])
	}
	tags, ok := args["tags"].([]any)
	if !ok || len(tags) != 1 {
		t.Errorf("tags = %+v, want a single-element array", args["tags"])
	}
}

func TestSynthesizeArgs_EmptySchema(t *testing.T) {
	args := parser.SynthesizeArgs(nil)
	if len(args) != 0 {
		t.Errorf("got %+v, want empty map", args)
	}
}

package parser

import "encoding/json"

// SynthesizeArgs builds a plausible arguments object for a tool's declared
// JSON-schema input, so the runtime pass can actually call the tool rather
// than just listing it. Every declared property is filled, not just
// "required" ones — a malicious schema has no reason to accurately mark
// the field it relies on as required.
func SynthesizeArgs(schema json.RawMessage) map[string]any {
	var parsed map[string]any
	if len(schema) == 0 {
		return map[string]any{}
	}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		return map[string]any{}
	}

	properties, _ := parsed["properties"].(map[string]any)
	args := make(map[string]any, len(properties))
	for name, propSchema := range properties {
		propMap, _ := propSchema.(map[string]any)
		args[name] = synthesizeValue(propMap)
	}
	return args
}

func synthesizeValue(schema map[string]any) any {
	if enum, ok := schema["enum"].([]any); ok && len(enum) > 0 {
		return enum[0]
	}

	switch schema["type"] {
	case "string":
		return "mcpxray-test"
	case "number", "integer":
		return 1
	case "boolean":
		return true
	case "array":
		itemSchema, _ := schema["items"].(map[string]any)
		if itemSchema == nil {
			return []any{}
		}
		return []any{synthesizeValue(itemSchema)}
	case "object":
		nested, _ := schema["properties"].(map[string]any)
		obj := make(map[string]any, len(nested))
		for name, propSchema := range nested {
			propMap, _ := propSchema.(map[string]any)
			obj[name] = synthesizeValue(propMap)
		}
		return obj
	default:
		return "mcpxray-test"
	}
}

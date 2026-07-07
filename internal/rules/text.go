package rules

import "github.com/ofaruk/mcp-x-ray/internal/parser"

// describedItem is a single tool/prompt/resource description, normalized so
// text-scanning rules don't each need their own manifest-walking loop.
type describedItem struct {
	Name  string
	Field string
	Text  string
}

func describedItems(m *parser.Manifest) []describedItem {
	items := make([]describedItem, 0, len(m.Tools)+len(m.Prompts)+len(m.Resources))
	for _, t := range m.Tools {
		if t.Description != "" {
			items = append(items, describedItem{Name: t.Name, Field: "description", Text: t.Description})
		}
	}
	for _, p := range m.Prompts {
		if p.Description != "" {
			items = append(items, describedItem{Name: p.Name, Field: "description", Text: p.Description})
		}
	}
	for _, r := range m.Resources {
		if r.Description != "" {
			items = append(items, describedItem{Name: r.Name, Field: "description", Text: r.Description})
		}
	}
	return items
}

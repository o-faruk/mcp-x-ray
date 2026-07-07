package report

import (
	"encoding/json"
	"io"
)

// WriteJSON serializes a Report as pretty-printed JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

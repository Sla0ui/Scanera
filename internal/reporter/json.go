package reporter

import (
	"encoding/json"
	"fmt"
	"os"
)

// GenerateJSON creates a JSON report
func (r *Reporter) GenerateJSON(outputPath string) error {
	jsonData, err := json.MarshalIndent(r.results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

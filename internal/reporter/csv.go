package reporter

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// GenerateCSV creates a CSV report
func (r *Reporter) GenerateCSV(outputPath string) error {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	rows := [][]string{{"Domain", "Status", "StatusCode", "FinalURL", "IPAddresses", "Server", "Technologies", "ResponseTime", "Title", "RedirectTo", "Findings"}}
	for _, result := range r.results {
		rows = append(rows, []string{
			result.Domain,
			statusLabel(result),
			strconv.Itoa(result.StatusCode),
			result.FinalURL,
			strings.Join(result.IPAddresses, "|"),
			result.ServerInfo.Server,
			strings.Join(result.Technologies, "|"),
			fmt.Sprintf("%dms", result.ResponseTime.Milliseconds()),
			oneLine(result.Title),
			result.RedirectTo,
			strconv.Itoa(len(result.Findings)),
		})
	}
	if err := writeCSVRows(w, rows); err != nil {
		return fmt.Errorf("failed to encode CSV: %w", err)
	}
	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write CSV file: %w", err)
	}
	return nil
}

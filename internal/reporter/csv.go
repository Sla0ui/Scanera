package reporter

import (
	"fmt"
	"os"
	"strings"
)

// GenerateCSV creates a CSV report
func (r *Reporter) GenerateCSV(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	file.WriteString("Domain,Status,StatusCode,FinalURL,IPAddresses,Server,Technologies,ResponseTime,Title,RedirectTo\n")

	for _, result := range r.results {
		status := "inactive"
		if result.Active {
			status = "active"
		}

		title := strings.ReplaceAll(result.Title, ",", " ")
		title = strings.ReplaceAll(title, "\n", " ")

		finalURL := strings.ReplaceAll(result.FinalURL, ",", "%2C")
		redirectTo := strings.ReplaceAll(result.RedirectTo, ",", "%2C")
		server := strings.ReplaceAll(result.ServerInfo.Server, ",", " ")
		ips := strings.Join(result.IPAddresses, "|")
		techs := strings.Join(result.Technologies, "|")

		file.WriteString(fmt.Sprintf(
			"%s,%s,%d,%s,%s,%s,%s,%dms,%s,%s\n",
			result.Domain,
			status,
			result.StatusCode,
			finalURL,
			ips,
			server,
			techs,
			result.ResponseTime.Milliseconds(),
			title,
			redirectTo,
		))
	}

	return nil
}

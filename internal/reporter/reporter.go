package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sla0ui/scanera/internal/models"
)

// Reporter handles generating scan reports in various formats
type Reporter struct {
	results   []*models.Result
	outputDir string
}

// New creates a new Reporter instance
func New(results []*models.Result, outputDir string) *Reporter {
	return &Reporter{
		results:   results,
		outputDir: outputDir,
	}
}

// WriteResultsToFiles writes results to standard output files
func (r *Reporter) WriteResultsToFiles() error {
	activeFile := filepath.Join(r.outputDir, "active_domains.txt")
	inactiveFile := filepath.Join(r.outputDir, "inactive_domains.txt")
	logFile := filepath.Join(r.outputDir, "domain_check_log.csv")
	jsonFile := filepath.Join(r.outputDir, "scan_results.json")

	// CSV log file
	logFd, err := os.Create(logFile)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	defer logFd.Close()

	logFd.WriteString("Domain,Status,StatusCode,FinalURL,RedirectTo,ResponseTime,Title,Server,IPAddresses,Error\n")

	for _, result := range r.results {
		status := "inactive"
		if result.Active {
			status = "active"
		}

		errorMsg := ""
		if result.Error != nil {
			errorMsg = result.Error.Error()
		}

		title := strings.ReplaceAll(result.Title, ",", " ")
		title = strings.ReplaceAll(title, "\n", " ")

		finalURL := strings.ReplaceAll(result.FinalURL, ",", "%2C")
		redirectTo := strings.ReplaceAll(result.RedirectTo, ",", "%2C")
		server := strings.ReplaceAll(result.ServerInfo.Server, ",", " ")
		ips := strings.Join(result.IPAddresses, "|")

		logFd.WriteString(fmt.Sprintf(
			"%s,%s,%d,%s,%s,%dms,%s,%s,%s,%s\n",
			result.Domain,
			status,
			result.StatusCode,
			finalURL,
			redirectTo,
			result.ResponseTime.Milliseconds(),
			title,
			server,
			ips,
			errorMsg,
		))
	}

	// JSON results
	jsonData, err := json.MarshalIndent(r.results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	if err := os.WriteFile(jsonFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	// Active/Inactive domains
	for _, result := range r.results {
		if result.Active {
			logLine := result.FinalURL
			if result.RedirectTo != "" {
				logLine += fmt.Sprintf(" (Redirected to: %s)", result.RedirectTo)
			}
			appendToFile(activeFile, logLine+"\n")
		} else {
			appendToFile(inactiveFile, result.Domain+"\n")
		}
	}

	return nil
}

// GenerateReport creates a report in the specified format
func (r *Reporter) GenerateReport(outputPath, format string) error {
	formats := strings.Split(format, ",")
	outputBase := strings.TrimSuffix(outputPath, filepath.Ext(outputPath))

	for _, fmt := range formats {
		switch strings.ToLower(strings.TrimSpace(fmt)) {
		case "json":
			if err := r.GenerateJSON(outputBase + ".json"); err != nil {
				return err
			}
		case "csv":
			if err := r.GenerateCSV(outputBase + ".csv"); err != nil {
				return err
			}
		case "html":
			if err := r.GenerateHTML(outputBase + ".html"); err != nil {
				return err
			}
		case "markdown", "md":
			if err := r.GenerateMarkdown(outputBase + ".md"); err != nil {
				return err
			}
		}
	}

	return nil
}

// GetStats returns active and inactive counts
func (r *Reporter) GetStats() (active, inactive int) {
	for _, result := range r.results {
		if result.Active {
			active++
		} else {
			inactive++
		}
	}
	return
}

func appendToFile(filename, text string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening file for append: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(text); err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	return nil
}

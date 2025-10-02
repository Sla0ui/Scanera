package reporter

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// GenerateHTML creates an HTML report
func (r *Reporter) GenerateHTML(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer file.Close()

	activeCount, inactiveCount := r.GetStats()

	// Write HTML header
	file.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scanera Domain Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
        h1, h2, h3 { color: #2c3e50; }
        .container { max-width: 1200px; margin: 0 auto; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { flex: 1; padding: 15px; border-radius: 5px; text-align: center; }
        .active { background-color: #d4edda; color: #155724; }
        .inactive { background-color: #f8d7da; color: #721c24; }
        .total { background-color: #e2e3e5; color: #383d41; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .badge { display: inline-block; padding: 3px 7px; border-radius: 3px; font-size: 12px; margin-right: 5px; }
        .badge-success { background-color: #d4edda; color: #155724; }
        .badge-danger { background-color: #f8d7da; color: #721c24; }
        .badge-tech { background-color: #cce5ff; color: #004085; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Scanera Domain Analysis Report</h1>
        <div class="summary">
            <p>Report generated on: ` + time.Now().Format("January 2, 2006 15:04:05") + `</p>
            <p>Total domains scanned: ` + strconv.Itoa(len(r.results)) + `</p>
        </div>

        <div class="stats">
            <div class="stat-box active">
                <h3>Active Domains</h3>
                <p>` + strconv.Itoa(activeCount) + `</p>
            </div>
            <div class="stat-box inactive">
                <h3>Inactive Domains</h3>
                <p>` + strconv.Itoa(inactiveCount) + `</p>
            </div>
            <div class="stat-box total">
                <h3>Total Domains</h3>
                <p>` + strconv.Itoa(len(r.results)) + `</p>
            </div>
        </div>

        <h2>Active Domains</h2>
        <table>
            <tr>
                <th>Domain</th>
                <th>Final URL</th>
                <th>Status</th>
                <th>Technologies</th>
                <th>Server</th>
                <th>Response Time</th>
            </tr>`)

	for _, result := range r.results {
		if result.Active {
			techStr := ""
			for _, tech := range result.Technologies {
				techStr += `<span class="badge badge-tech">` + tech + `</span>`
			}

			file.WriteString(`
            <tr>
                <td>` + result.Domain + `</td>
                <td>` + result.FinalURL + `</td>
                <td><span class="badge badge-success">Active</span></td>
                <td>` + techStr + `</td>
                <td>` + result.ServerInfo.Server + `</td>
                <td>` + strconv.FormatInt(result.ResponseTime.Milliseconds(), 10) + `ms</td>
            </tr>`)
		}
	}

	file.WriteString(`
        </table>

        <h2>Inactive Domains</h2>
        <table>
            <tr>
                <th>Domain</th>
                <th>Status</th>
                <th>Status Code</th>
                <th>Error</th>
            </tr>`)

	for _, result := range r.results {
		if !result.Active {
			errMsg := ""
			if result.Error != nil {
				errMsg = result.Error.Error()
			}

			file.WriteString(`
            <tr>
                <td>` + result.Domain + `</td>
                <td><span class="badge badge-danger">Inactive</span></td>
                <td>` + strconv.Itoa(result.StatusCode) + `</td>
                <td>` + errMsg + `</td>
            </tr>`)
		}
	}

	file.WriteString(`
        </table>
    </div>
</body>
</html>`)

	return nil
}

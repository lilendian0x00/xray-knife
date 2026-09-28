package cfscanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/spf13/cobra"
)

var (
	listLimit int
	listJSON  bool
)

// storedScan is a database row in the shape list-results prints as JSON.
type storedScan struct {
	IP            string    `json:"ip"`
	LatencyMs     *int64    `json:"latencyMs,omitempty"`
	DownloadMbps  float64   `json:"downloadMbps,omitempty"`
	UploadMbps    float64   `json:"uploadMbps,omitempty"`
	Error         string    `json:"error,omitempty"`
	LastScannedAt time.Time `json:"lastScannedAt"`
}

func toStoredScan(res database.CfScanResult) storedScan {
	out := storedScan{
		IP:            res.IP,
		DownloadMbps:  res.DownloadMbps.Float64,
		UploadMbps:    res.UploadMbps.Float64,
		Error:         res.Error.String,
		LastScannedAt: res.LastScannedAt,
	}
	if res.LatencyMs.Valid {
		ms := res.LatencyMs.Int64
		out.LatencyMs = &ms
	}
	return out
}

// listResultsCmd prints CF scanner results from the database.
var listResultsCmd = &cobra.Command{
	Use:   "list-results",
	Short: "Lists the results from the CF scanner from the database",
	RunE: func(cmd *cobra.Command, args []string) error {
		results, err := database.GetCfScanHistory(listLimit)
		if err != nil {
			return err
		}

		if listJSON {
			rows := make([]storedScan, 0, len(results))
			for _, res := range results {
				rows = append(rows, toStoredScan(res))
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rows)
		}

		if len(results) == 0 {
			fmt.Println("No CF scanner results found in the database.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "IP\tLATENCY\tDOWNLOAD\tUPLOAD\tERROR\tLAST SCANNED")
		fmt.Fprintln(w, "--\t-------\t--------\t------\t-----\t------------")

		for _, res := range results {
			latency := "N/A"
			if res.LatencyMs.Valid {
				latency = strconv.FormatInt(res.LatencyMs.Int64, 10) + "ms"
			}

			download := "N/A"
			if res.DownloadMbps.Valid && res.DownloadMbps.Float64 > 0 {
				download = fmt.Sprintf("%.2f Mbps", res.DownloadMbps.Float64)
			}

			upload := "N/A"
			if res.UploadMbps.Valid && res.UploadMbps.Float64 > 0 {
				upload = fmt.Sprintf("%.2f Mbps", res.UploadMbps.Float64)
			}

			errorMsg := "None"
			if res.Error.Valid && res.Error.String != "" {
				errorMsg = res.Error.String
				// Truncate long error messages for better table display
				if len(errorMsg) > 40 {
					errorMsg = errorMsg[:37] + "..."
				}
			}

			lastScanned := res.LastScannedAt.Format("2006-01-02 15:04")

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", res.IP, latency, download, upload, errorMsg, lastScanned)
		}

		return w.Flush()
	},
}

func init() {
	listResultsCmd.Flags().IntVarP(&listLimit, "limit", "l", 100, "Limit the number of results to show")
	listResultsCmd.Flags().BoolVarP(&listJSON, "json", "j", false, "Print the results as JSON")
	CFscannerCmd.AddCommand(listResultsCmd)
}

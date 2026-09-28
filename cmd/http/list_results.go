package http

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/lilendian0x00/xray-knife/v11/database"
	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
	"github.com/spf13/cobra"
)

var (
	listLimit int
	listJSON  bool
)

// storedResult is a database row in the shape list-results prints as JSON:
// plain fields instead of sql.Null*, plus the failure kind.
type storedResult struct {
	RunID         int64   `json:"runId"`
	Link          string  `json:"link"`
	Status        string  `json:"status"`
	FailureKind   string  `json:"failureKind,omitempty"`
	Reason        string  `json:"reason,omitempty"`
	DelayMs       int64   `json:"delayMs"`
	DownloadMbps  float64 `json:"downloadMbps"`
	UploadMbps    float64 `json:"uploadMbps"`
	IP            string  `json:"ip,omitempty"`
	Location      string  `json:"location,omitempty"`
	TTFBMs        int64   `json:"ttfbMs"`
	ConnectTimeMs int64   `json:"connectTimeMs"`
}

func toStoredResult(res database.HttpTestResult) storedResult {
	return storedResult{
		RunID:         res.RunID,
		Link:          res.ConfigLink,
		Status:        res.Status,
		FailureKind:   storedKind(res),
		Reason:        res.Reason.String,
		DelayMs:       res.DelayMs,
		DownloadMbps:  res.DownloadMbps,
		UploadMbps:    res.UploadMbps,
		IP:            res.IPAddress.String,
		Location:      res.IPLocation.String,
		TTFBMs:        res.TTFBMs,
		ConnectTimeMs: res.ConnectTimeMs,
	}
}

// listResultsCmd prints HTTP test results from the database.
var listResultsCmd = &cobra.Command{
	Use:   "list-results",
	Short: "Lists the results from the last HTTP test run from the database",
	RunE: func(cmd *cobra.Command, args []string) error {
		results, err := database.GetHttpTestHistory(listLimit)
		if err != nil {
			return err
		}

		if listJSON {
			rows := make([]storedResult, 0, len(results))
			for _, res := range results {
				rows = append(rows, toStoredResult(res))
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rows)
		}

		if len(results) == 0 {
			fmt.Println("No test results found in the database.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "STATUS\tKIND\tDELAY\tDOWNLOAD\tUPLOAD\tLOCATION\tLINK")
		fmt.Fprintln(w, "------\t----\t-----\t--------\t------\t--------\t----")

		for _, res := range results {
			delay := "N/A"
			if res.DelayMs >= 0 {
				delay = strconv.FormatInt(res.DelayMs, 10) + "ms"
			}

			download := "N/A"
			if res.DownloadMbps > 0 {
				download = fmt.Sprintf("%.2f Mbps", res.DownloadMbps)
			}

			upload := "N/A"
			if res.UploadMbps > 0 {
				upload = fmt.Sprintf("%.2f Mbps", res.UploadMbps)
			}

			location := "N/A"
			if res.IPLocation.Valid {
				location = res.IPLocation.String
			}

			kind := storedKind(res)
			if kind == "" {
				kind = "-"
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", res.Status, kind, delay, download, upload, location, res.ConfigLink)
		}

		return w.Flush()
	},
}

func init() {
	listResultsCmd.Flags().IntVarP(&listLimit, "limit", "l", 100, "Limit the number of results to show")
	listResultsCmd.Flags().BoolVarP(&listJSON, "json", "j", false, "Print the results as JSON")
	HttpCmd.AddCommand(listResultsCmd)
}

// storedKind prefers the failure kind saved with the result and falls back
// to recovering it from the reason for rows written before migration 0004.
func storedKind(res database.HttpTestResult) string {
	if res.FailureKind.Valid && res.FailureKind.String != "" {
		return res.FailureKind.String
	}
	return pkghttp.KindFromReason(res.Status, res.Reason.String)
}

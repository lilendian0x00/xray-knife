package http

import (
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/lilendian0x00/xray-knife/v6/database"
	"github.com/spf13/cobra"
)

var listLimit int

// listResultsCmd represents the list-results command
var listResultsCmd = &cobra.Command{
	Use:   "list-results",
	Short: "Lists the results from the last HTTP test run from the database",
	RunE: func(cmd *cobra.Command, args []string) error {
		results, err := database.GetHttpTestHistory(listLimit)
		if err != nil {
			return err
		}

		if len(results) == 0 {
			fmt.Println("No test results found in the database.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "STATUS\tDELAY\tDOWNLOAD\tUPLOAD\tLOCATION\tLINK")
		fmt.Fprintln(w, "------\t-----\t--------\t------\t--------\t----")

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

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", res.Status, delay, download, upload, location, res.ConfigLink)
		}

		return w.Flush()
	},
}

func init() {
	listResultsCmd.Flags().IntVarP(&listLimit, "limit", "l", 100, "Limit the number of results to show")
	HttpCmd.AddCommand(listResultsCmd)
}

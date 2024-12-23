package net

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v2/utils"
	"github.com/lilendian0x00/xray-knife/v2/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v2/xray"
	"github.com/spf13/cobra"
)

var (
	configLinksFile     string
	outputFile          string
	outputType          string
	threadCount         uint16
	destURL             string
	httpMethod          string
	showBody            bool
	insecureTLS         bool
	verbose             bool
	sortedByRealDelay   bool
	speedtest           bool
	getIPInfo           bool
	speedtestAmount     uint32
	maximumAllowedDelay uint16
)

var validConfigs []string
var validConfigsMu sync.Mutex

type ConfigResults []*xray.Result

func (cResults ConfigResults) Len() int {
	return len(cResults)
}

func (cResults ConfigResults) Less(i, j int) bool {
	if (cResults[i].Delay < cResults[j].Delay) && (cResults[i].DownloadSpeed >= cResults[j].DownloadSpeed) && (cResults[i].UploadSpeed >= cResults[j].UploadSpeed) {
		return true
	} /*else if cResults[i].Delay == cResults[j].Delay {
		return cResults[i].ConfigLink < cResults[j].ConfigLink
	}*/
	return false
}

func (cResults ConfigResults) Swap(i, j int) {
	cResults[i], cResults[j] = cResults[j], cResults[i]
}

func HttpTestMultipleConfigs(examiner xray.Examiner, links []string, threadCount uint16, verbose bool) ConfigResults {
	d := color.New(color.FgCyan, color.Bold)

	// Limit the number of concurrent workers
	semaphore := make(chan int, threadCount)

	// Wait for all workers to finish
	wg := sync.WaitGroup{}

	var confRes ConfigResults

	for i := 0; i < len(links); i++ {
		semaphore <- 1
		wg.Add(1)
		go func(configIndex int) {
			defer func() {
				// Free the worker at the end
				<-semaphore
				wg.Done()
			}()

			res, err := examiner.ExamineConfig(links[configIndex])
			if err != nil {
				if verbose {
					customlog.Printf(customlog.Failure, "Error: %s - broken config: %s\n", err.Error(), links[configIndex])
				}
				return
			}

			if res.Status == "passed" {
				if verbose {
					d.Printf("Config Number: %d\n", configIndex+1)
					fmt.Printf("%v", res.Protocol.DetailsStr())
					customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", res.Delay)
				}
			}

			if outputType == "csv" || res.Status == "passed" {
				// Save both passed and failed configs if we save as csv
				validConfigsMu.Lock()
				confRes = append(confRes, &res)
				validConfigsMu.Unlock()
			}
			return
		}(i)
	}
	// Wait for all goroutines to finish
	wg.Wait()

	// Close semaphore channel
	close(semaphore)

	return confRes
}

// HttpCmd represents the http command
var HttpCmd = &cobra.Command{
	Use:   "http",
	Short: "Examine config[s] real delay using http request",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		examiner := xray.Examiner{
			Xs:                     xray.NewXrayService(verbose, insecureTLS),
			MaxDelay:               maximumAllowedDelay,
			Logs:                   false,
			ShowBody:               false,
			DoSpeedtest:            speedtest,
			DoIPInfo:               getIPInfo,
			TestEndpoint:           destURL,
			TestEndpointHttpMethod: httpMethod,
			SpeedtestAmount:        speedtestAmount,
		}

		switch outputType {
		case "csv":
			base := strings.TrimSuffix(outputFile, filepath.Ext(outputFile))
			outputFile = base + ".csv"
			break
		case "txt":
			break
		default:
			customlog.Printf(customlog.Failure, "Bad output format!\nAllowed formats: txt, csv\n")
			os.Exit(1)
		}

		if configLinksFile != "" {
			links := utils.ParseFileByNewline(configLinksFile)
			fmt.Printf("%s: %d\n%s: %d\n%s: %dms\n%s: %t\n%s: %s\n%s: %t\n%s: %t\n%s: %s\n%s: %t\n\n",
				color.RedString("Total configs"), len(links),
				color.RedString("Thread count"), threadCount,
				color.RedString("Maximum delay"), maximumAllowedDelay,
				color.RedString("Speed test"), speedtest,
				color.RedString("Test url"), destURL,
				color.RedString("IP info"), getIPInfo,
				color.RedString("Insecure TLS"), insecureTLS,
				color.RedString("Output type"), outputType,
				color.RedString("Verbose"), verbose)

			if speedtest && outputType != "csv" {
				customlog.Printf(customlog.Processing, "Speedtest is enabled, switching to CSV output!\n\n")
				outputType = "csv"
			}

			confRes := HttpTestMultipleConfigs(examiner, links, threadCount, true)

			// Sort configs based on their delay
			if sortedByRealDelay {
				sort.Sort(confRes)
			}

			if outputType == "txt" {
				for _, v := range confRes {
					if v.Status == "passed" {
						validConfigs = append(validConfigs, v.ConfigLink)
					}
				}

				// Save configs
				err := utils.WriteIntoFile(outputFile, []byte(strings.Join(validConfigs, "\n\n")))
				if err != nil {
					customlog.Printf(customlog.Failure, "Saving configs failed due to the error: %v\n", err)
					os.Exit(1)
				}
				customlog.Printf(customlog.Finished, "A total of %d working configurations have been saved to %s\n", len(validConfigs), outputFile)
			} else if outputType == "csv" {
				out, err := gocsv.MarshalString(&confRes)
				if err != nil {
					customlog.Printf(customlog.Failure, "Saving configs failed due to the error: %v\n", err)
					os.Exit(1)
				}
				err = utils.WriteIntoFile(outputFile, []byte(out))
				if err != nil {
					customlog.Printf(customlog.Failure, "Saving configs failed due to the error: %v\n", err)
					os.Exit(1)
				}

				customlog.Printf(customlog.Finished, "A total of %d configurations have been saved to %s\n", len(confRes), outputFile)
			}

		} else {
			examiner.Logs = true
			res, err := examiner.ExamineConfig(configLink)
			if err != nil {
				customlog.Printf(customlog.Failure, "%s\n", err)
				return
			}

			if res.Status == "failed" {
				customlog.Printf(customlog.Failure, "Config didn't respond!\n")
			} else {
				customlog.Printf(customlog.Success, "Real Delay: %dms\n", res.Delay)
				if speedtest {
					customlog.Printf(customlog.Success, "Downloaded %dKB - Speed: %f mbps\n", speedtestAmount, res.DownloadSpeed)
					customlog.Printf(customlog.Success, "Uploaded %dKB - Speed: %f mbps\n", speedtestAmount, res.UploadSpeed)
				}
			}
		}

	},
}

func init() {
	HttpCmd.Flags().StringVarP(&configLink, "config", "c", "", "The xray config link")
	HttpCmd.Flags().StringVarP(&configLinksFile, "file", "f", "", "Read config links from a file")
	HttpCmd.Flags().Uint16VarP(&threadCount, "thread", "t", 5, "Number of threads to be used for checking links from file")
	HttpCmd.Flags().StringVarP(&destURL, "url", "u", "https://google.com/", "The url to test config")
	HttpCmd.Flags().StringVarP(&httpMethod, "method", "m", "GET", "Http method")
	HttpCmd.Flags().BoolVarP(&showBody, "body", "b", false, "Show response body")
	HttpCmd.Flags().Uint16VarP(&maximumAllowedDelay, "mdelay", "d", 10000, "Maximum allowed delay")
	HttpCmd.Flags().BoolVarP(&insecureTLS, "insecure", "e", false, "Insecure tls connection (fake SNI)")
	HttpCmd.Flags().BoolVarP(&speedtest, "speedtest", "p", false, "Speed test with speed.cloudflare.com")
	HttpCmd.Flags().BoolVarP(&getIPInfo, "rip", "r", false, "Send request to XXXX/cdn-cgi/trace to receive config's IP details")
	HttpCmd.Flags().Uint32VarP(&speedtestAmount, "amount", "a", 10000, "Download and upload amount (KB)")
	HttpCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose xray-core")
	HttpCmd.Flags().StringVarP(&outputType, "type", "x", "txt", "Output type (txt, csv)")
	HttpCmd.Flags().StringVarP(&outputFile, "out", "o", "valid.txt", "Output file for valid config links")
	HttpCmd.Flags().BoolVarP(&sortedByRealDelay, "sort", "s", true, "Sort config links by their delay (fast to slow)")
}

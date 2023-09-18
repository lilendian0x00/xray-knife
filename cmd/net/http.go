package net

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/gocarina/gocsv"
	"github.com/spf13/cobra"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"xray-knife/speedtester/cloudflare"
	"xray-knife/utils"
	"xray-knife/utils/customlog"
	"xray-knife/xray"
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

var (
	failedDelay int64 = 99999
)

var validConfigs []string
var validConfigsMu sync.Mutex

type result struct {
	ConfigLink    string  `csv:"link"`     // vmess://... vless//..., etc
	Status        string  `csv:"status"`   // passed, semi-passed, failed
	TLS           string  `csv:"tls"`      // none, tls, reality
	RealIPAddr    string  `csv:"ip"`       // Real ip address (req to cloudflare.com/cdn-cgi/trace)
	Delay         int64   `csv:"delay"`    // millisecond
	DownloadSpeed float32 `csv:"download"` // mbps
	UploadSpeed   float32 `csv:"upload"`   // mbps
	IpAddrLoc     string  `csv:"location"` // IP address location
}

type configResults []*result

func (cResults configResults) Len() int {
	return len(cResults)
}

func (cResults configResults) Less(i, j int) bool {
	if (cResults[i].Delay < cResults[j].Delay) && (cResults[i].DownloadSpeed >= cResults[j].DownloadSpeed) && (cResults[i].UploadSpeed >= cResults[j].UploadSpeed) {
		return true
	} /*else if cResults[i].Delay == cResults[j].Delay {
		return cResults[i].ConfigLink < cResults[j].ConfigLink
	}*/
	return false
}

func (cResults configResults) Swap(i, j int) {
	cResults[i], cResults[j] = cResults[j], cResults[i]
}

var confRes configResults

// HttpCmd represents the http command
var HttpCmd = &cobra.Command{
	Use:   "http",
	Short: "Examine config[s] real delay using http request",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		xs := xray.NewXrayService(verbose, insecureTLS)

		if configLinksFile != "" {
			d := color.New(color.FgCyan, color.Bold)

			// Limit the number of concurrent workers
			semaphore := make(chan int, threadCount)

			// Wait for all workers to finish
			wg := sync.WaitGroup{}

			links := utils.ParseFileByNewline(configLinksFile)

			for i := 0; i < len(links); i++ {
				semaphore <- 1
				wg.Add(1)
				go func(configIndex int) {
					defer func() {
						// Free the worker at the end
						<-semaphore
						wg.Done()
					}()

					parsed, err := xray.ParseXrayConfig(links[configIndex])
					if err != nil {
						customlog.Printf(customlog.Failure, "Couldn't parse the config!\n\n")
						return
						//os.Exit(1)
					}

					r := &result{
						ConfigLink: links[configIndex],
						Status:     "passed",
						TLS:        parsed.ConvertToGeneralConfig().TLS,
						Delay:      failedDelay,
						RealIPAddr: "null",
					}
					defer func() {
						if speedtest && r.Status == "passed" && /*r.Delay != failedDelay &&*/ (r.UploadSpeed == 0 || r.DownloadSpeed == 0) {
							r.Status = "semi-passed"
						}

						if outputType == "csv" {
							// Save both passed and failed configs
							validConfigsMu.Lock()
							confRes = append(confRes, r)
							validConfigsMu.Unlock()
						} else if r.Status == "passed" {
							// Only save working configs
							validConfigsMu.Lock()
							confRes = append(confRes, r)
							validConfigsMu.Unlock()
						}
					}()

					instance, err1 := xs.StartXray(parsed)
					if err1 != nil {
						customlog.Printf(customlog.Failure, "Couldn't start the xray! : %v\n\n", err1)
						return
					}
					// Close xray conn after testing
					defer instance.Close()

					var delay int64
					var downloadTime int64
					var uploadTime int64

					delay, _, err = xray.MeasureDelay(instance, time.Duration(15)*time.Second, showBody, destURL, httpMethod)
					if err != nil {
						//customlog.Printf(customlog.Failure, "Config didn't respond!\n\n")
						r.Status = "failed"
						return
						//os.Exit(1)
					}
					r.Delay = delay

					if uint16(delay) > maximumAllowedDelay {
						r.Status = "timeout"
						return
					} else {
						d.Printf("Config Number: %d\n", configIndex+1)
						fmt.Printf("%v", parsed.DetailsStr())
						customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", delay)
					}

					if getIPInfo {
						_, body, err := xray.CoreHTTPRequestCustom(instance, time.Duration(20)*time.Second, cloudflare.Speedtest.MakeDebugRequest())
						if err != nil {
							//customlog.Printf(customlog.Failure, "Download failed!\n")
							//return
						} else {
							for _, line := range strings.Split(string(body), "\n") {
								s := strings.SplitN(line, "=", 2)
								if s[0] == "ip" {
									r.RealIPAddr = s[1]
								} else if s[0] == "loc" {
									r.IpAddrLoc = s[1]
									break
								}
							}

						}
					}

					if speedtest {
						downloadStartTime := time.Now()
						_, _, err := xray.CoreHTTPRequestCustom(instance, time.Duration(20)*time.Second, cloudflare.Speedtest.MakeDownloadHTTPRequest(false, speedtestAmount*1000))
						if err != nil {
							//customlog.Printf(customlog.Failure, "Download failed!\n")
							//return
						} else {
							downloadTime = time.Since(downloadStartTime).Milliseconds()
							r.DownloadSpeed = (float32((speedtestAmount*1000)*8) / (float32(downloadTime) / float32(1000.0))) / float32(1000000.0)
							//customlog.Printf(customlog.Success, "Download took: %dms\n", downloadTime)
						}

						uploadStartTime := time.Now()
						_, _, err = xray.CoreHTTPRequestCustom(instance, time.Duration(20)*time.Second, cloudflare.Speedtest.MakeUploadHTTPRequest(false, speedtestAmount*1000))
						if err != nil {
							//customlog.Printf(customlog.Failure, "Upload failed!\n")
							//return
						} else {
							uploadTime = time.Since(uploadStartTime).Milliseconds()
							r.UploadSpeed = (float32((speedtestAmount*1000)*8) / (float32(uploadTime) / float32(1000.0))) / float32(1000000.0)
							//customlog.Printf(customlog.Success, "Upload took: %dms\n", uploadTime)
						}
					}

					return
				}(i)
			}
			// Wait for all goroutines to finish
			wg.Wait()

			// Close semaphore channel
			close(semaphore)

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
				if outputFile == "valid.txt" {
					outputFile = "valid.csv"
				}
				//writer := csv.NewWriter(f)
				//defer writer.Flush()

				//writer.Write(headers)
				//for _, row := range rows {
				//	writer.Write(row)
				//}
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
			parsed, err := xray.ParseXrayConfig(configLink)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				os.Exit(1)
			}

			fmt.Println("\n" + parsed.DetailsStr())

			instance, err := xs.StartXray(parsed)
			if err != nil {
				customlog.Printf(customlog.Failure, "Couldn't start the xray! : %v\n\n", err)
				os.Exit(1)
				return
			}

			delay, _, err := xray.MeasureDelay(instance, time.Duration(15)*time.Second, showBody, destURL, httpMethod)
			if err != nil {
				customlog.Printf(customlog.Failure, "Config didn't respond!\n")
				os.Exit(1)
			}
			customlog.Printf(customlog.Success, "Real Delay: %dms\n", delay)
			if speedtest {
				downloadStartTime := time.Now()
				_, _, err := xray.CoreHTTPRequestCustom(instance, time.Duration(60)*time.Second, cloudflare.Speedtest.MakeDownloadHTTPRequest(false, speedtestAmount*1000))
				if err != nil {
					customlog.Printf(customlog.Failure, "Download failed!  : %v\n", err)
					//return
				} else {
					downloadTime := time.Since(downloadStartTime).Milliseconds()

					customlog.Printf(customlog.Success, "Downloaded %dKB - Speed: %f mbps\n", speedtestAmount, (float32((speedtestAmount*1000)*8)/(float32(downloadTime)/float32(1000.0)))/float32(1000000.0))
				}

				uploadStartTime := time.Now()
				_, _, err = xray.CoreHTTPRequestCustom(instance, time.Duration(60)*time.Second, cloudflare.Speedtest.MakeUploadHTTPRequest(false, speedtestAmount*1000))
				if err != nil {
					customlog.Printf(customlog.Failure, "Upload failed! : %v\n", err)
					//return
				} else {
					uploadTime := time.Since(uploadStartTime).Milliseconds()

					customlog.Printf(customlog.Success, "Uploaded %dKB - Speed: %f mbps\n", speedtestAmount, (float32((speedtestAmount*1000)*8)/(float32(uploadTime)/float32(1000.0)))/float32(1000000.0))
				}

			}
			//fmt.Printf("%s: %sms\n", color.RedString("Real delay"), color.YellowString(strconv.Itoa(int(delay))))
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
	HttpCmd.Flags().Uint16VarP(&maximumAllowedDelay, "mdelay", "d", 3000, "Maximum allowed delay")
	HttpCmd.Flags().BoolVarP(&insecureTLS, "insecure", "e", false, "Insecure tls connection (fake SNI)")
	HttpCmd.Flags().BoolVarP(&speedtest, "speedtest", "p", false, "Speed test with speed.cloudflare.com")
	HttpCmd.Flags().BoolVarP(&getIPInfo, "rip", "r", false, "Send request to XXXX/cdn-cgi/trace to receive config's IP details")
	HttpCmd.Flags().Uint32VarP(&speedtestAmount, "amount", "a", 10000, "Download and upload amount (KB)")
	HttpCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose xray-core")
	HttpCmd.Flags().StringVarP(&outputType, "type", "x", "txt", "Output type (csv, txt)")
	HttpCmd.Flags().StringVarP(&outputFile, "out", "o", "valid.txt", "Output file for valid config links")
	HttpCmd.Flags().BoolVarP(&sortedByRealDelay, "sort", "s", true, "Sort config links by their delay (fast to slow)")
}

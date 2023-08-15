package net

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"xray-knife/utils"
	"xray-knife/utils/customlog"
	"xray-knife/xray"
)

var (
	configLink      string
	configLinksFile string
	saveFile        string
	threadCount     uint16
	destURL         string
	httpMethod      string
	showBody        bool
	verbose         bool
)

var validConfigs []string
var validConfigsMu sync.Mutex

// HttpCmd represents the http command
var HttpCmd = &cobra.Command{
	Use:   "http",
	Short: "Examine config[s] real delay using http request",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
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
					// Free the worker at the end
					defer func() {
						<-semaphore
						wg.Done()
					}()
					d.Printf("Config Number: %d\n", configIndex+1)
					parsed, err := xray.ParseXrayConfig(links[configIndex])
					if err != nil {
						customlog.Printf(customlog.Failure, "Couldn't parse the config!\n\n")
						return
						//os.Exit(1)
					}
					instance, err1 := xray.StartXray(parsed, verbose, false)
					if err1 != nil {
						customlog.Printf(customlog.Failure, "Couldn't start the xray! : %v\n\n", err)
						return
					}
					delay, _, err2 := xray.MeasureDelay(instance, time.Duration(15)*time.Second, showBody, destURL, httpMethod)
					if err2 != nil {
						customlog.Printf(customlog.Failure, "Config didn't respond!\n\n")
						return
						//os.Exit(1)
					}
					fmt.Printf("%v", parsed.DetailsStr())
					customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", delay)
					validConfigsMu.Lock()
					validConfigs = append(validConfigs, links[configIndex])
					validConfigsMu.Unlock()
					return
				}(i)
			}
			wg.Wait()

			// Save configs

			err := utils.WriteIntoFile(saveFile, []byte(strings.Join(validConfigs, "\n\n")))
			if err != nil {
				customlog.Printf(customlog.Failure, "Config save configs due to file error!\n")
				os.Exit(1)
			}
			customlog.Printf(customlog.Finished, "%d number of configs have been saved into %s\n", len(validConfigs), saveFile)
		} else {
			parsed, err := xray.ParseXrayConfig(configLink)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				os.Exit(1)
			}

			fmt.Println("\n" + parsed.DetailsStr())

			instance, err := xray.StartXray(parsed, verbose, false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				os.Exit(1)
				return
			}

			delay, _, err := xray.MeasureDelay(instance, time.Duration(15)*time.Second, showBody, destURL, httpMethod)
			if err != nil {
				customlog.Printf(customlog.Failure, "Config didn't respond!")
				os.Exit(1)
			}
			fmt.Printf("%s: %sms\n", color.RedString("Real delay"), color.YellowString(strconv.Itoa(int(delay))))
		}

	},
}

func init() {
	HttpCmd.Flags().StringVarP(&configLink, "config", "c", "", "The xray config link")
	HttpCmd.Flags().StringVarP(&configLinksFile, "file", "f", "", "Read config links from a file")
	HttpCmd.Flags().Uint16VarP(&threadCount, "thread", "t", 5, "Number of threads to be used for checking links from file")
	HttpCmd.Flags().StringVarP(&destURL, "url", "u", "http://api.ipify.org/", "The url to test config")
	HttpCmd.Flags().StringVarP(&httpMethod, "method", "m", "GET", "Http method")
	HttpCmd.Flags().BoolVarP(&showBody, "body", "b", false, "Show response body")
	HttpCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose xray-core")
	HttpCmd.Flags().StringVarP(&saveFile, "out", "o", "valid.txt", "Output file for valid config links")

}

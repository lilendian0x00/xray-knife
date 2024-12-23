package speedtester

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/lilendian0x00/xray-knife/v2/network/customtls"
	"github.com/lilendian0x00/xray-knife/v2/speedtester/custom"
)

type SpeedTester struct {
	tester TesterI

	// Custom speedtest endpoint
	customSpeedtestEndpoint bool
	NoTls                   bool

	downloadAmount uint32
	uploadAmount   uint32

	downloadRequest *http.Request
	uploadRequest   *http.Request
}

type SpeedTesterOption = func(c *SpeedTester)

func WithCustomTester(host string, port uint16, noSSL bool, dpath string, upath string) SpeedTesterOption {
	return func(c *SpeedTester) {
		c.customSpeedtestEndpoint = true
		c.NoTls = noSSL
		c.tester = &custom.SpeedTester{
			SNI:              host,
			DownloadEndpoint: dpath,
			UploadEndpoint:   upath,
		}
	}
}

func WithCustomAmount(dw uint32, up uint32) SpeedTesterOption {
	return func(c *SpeedTester) {
		c.downloadAmount = dw
		c.uploadAmount = up
	}
}

func NewSpeedTester(tester TesterI, opts ...SpeedTesterOption) *SpeedTester {
	s := &SpeedTester{
		tester:         tester,
		downloadAmount: 10000000,
		uploadAmount:   10000000,
	}
	for _, opt := range opts {
		opt(s)
	}

	/*if s.customSpeedtestEndpoint {
		tester =
	} else {
		if tester != nil {
			s.downloadRequest = tester.MakeDownloadHTTPRequest(false, 10000000)
			s.uploadRequest = tester.MakeUploadHTTPRequest(false, 10000000)
		} else {
			customlog.Printf(customlog.Failure, "tester interface is empty!\n")
		}
	}*/

	s.downloadRequest = s.tester.MakeDownloadHTTPRequest(s.NoTls, s.downloadAmount)
	s.uploadRequest = s.tester.MakeUploadHTTPRequest(s.NoTls, s.uploadAmount)

	return s
}

func (s *SpeedTester) startDownloadTest(address string) (int64, error) {
	dialConn, err := net.DialTimeout("tcp", address, time.Second*30)
	if err != nil {
		return -1, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn, err := customtls.MakeUTLSConn(dialConn, s.downloadRequest.Host)
	if err != nil {
		return -1, err
	}

	resp, err := customtls.HttpOverUTLSConn(uTlsConn, s.downloadRequest, uTlsConn.ConnectionState().NegotiatedProtocol)
	if err != nil {
		return -1, err
	}

	start := time.Now()
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return -1, err
	}
	duration := time.Since(start).Milliseconds()

	resp.Body.Close()
	uTlsConn.Close()
	dialConn.Close()
	return duration, nil
}

func (s *SpeedTester) startUploadTest(address string) (int64, error) {
	dialConn, err := net.DialTimeout("tcp", address, time.Second*30)
	if err != nil {
		return -1, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn, err := customtls.MakeUTLSConn(dialConn, s.uploadRequest.Host)
	if err != nil {
		return -1, err
	}

	start := time.Now()
	resp, err := customtls.HttpOverUTLSConn(uTlsConn, s.uploadRequest, uTlsConn.ConnectionState().NegotiatedProtocol)
	if err != nil {
		return -1, err
	}
	duration := time.Since(start).Milliseconds()

	resp.Body.Close()
	uTlsConn.Close()
	dialConn.Close()
	return duration, nil
}

//type SpeedTesterI interface {
//	startDownloadTest() error
//	StartUploadTest() error
//}
//
//type SpeedTestDecorator struct {
//	original SpeedTesterI
//}
//
//func (d *SpeedTestDecorator) startDownloadTest() error {
//	// measure delay before calling original download method
//	start := time.Now()
//	err := d.original.startDownloadTest()
//	duration := time.Since(start)
//
//	// log or handle the duration as per your requirements
//
//	return err
//}
//
//func (d *SpeedTestDecorator) StartUploadTest() error {
//	// measure delay before calling original upload method
//	start := time.Now()
//	err := d.original.StartUploadTest()
//	duration := time.Since(start)
//
//	// log or handle the duration as per your requirements
//
//	return err
//}

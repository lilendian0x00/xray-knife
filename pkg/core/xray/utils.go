package xray

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func MeasureDelay(inst *core.Instance, timeout time.Duration, showBody bool, dest string, httpMethod string) (int64, int, error) {
	start := time.Now()
	code, body, err := CoreHTTPRequest(inst, timeout, httpMethod, dest)
	if err != nil {
		return -1, -1, err
	}
	//fmt.Printf("%s: %d\n", color.YellowString("Status code"), code)
	if showBody {
		fmt.Printf("Response body: \n%s\n", body)
	}
	return time.Since(start).Milliseconds(), code, nil
}

func CoreHTTPRequest(inst *core.Instance, timeout time.Duration, method, dest string) (int, []byte, error) {
	client, err := httpClient(inst, timeout)
	if err != nil {
		return 0, nil, err
	}

	req, _ := http.NewRequest(method, dest, nil)
	resp, err := client.Do(req)
	if err != nil {
		return -1, nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func httpClient(inst *core.Instance, timeout time.Duration) (*http.Client, error) {
	if inst == nil {
		return nil, errors.New("core instance nil")
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := xraynet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, inst, dest)
		},
	}

	c := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	return c, nil
}

func CoreHTTPRequestCustom(inst *core.Instance, timeout time.Duration, req *http.Request) (int, []byte, error) {
	c, err := httpClient(inst, timeout)
	if err != nil {
		return 0, nil, err
	}

	resp, err := c.Do(req)
	if err != nil {
		return -1, nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, b, nil
}

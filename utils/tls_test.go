package utils

import (
	"io"
	"net/url"
	"testing"
)

func TestTlsSendHTTPRequest(t *testing.T) {
	ll, _ := url.Parse("https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/reality")
	response, err := SendHTTPRequest(ll, "", "GET")
	if err != nil {
		t.Errorf("Http request error: %v", err)
	}
	_, _ = io.ReadAll(response.Body)
	response.Body.Close()
	t.Logf("Got %d", response.StatusCode)
	if response.StatusCode != 200 {
		t.Errorf("got %d, wanted %d", response.StatusCode, 200)
	}

}

package speedtester

import "net/http"

type TesterI interface {
	MakeDownloadHTTPRequest(noTLS bool, amount uint32) *http.Request
	MakeUploadHTTPRequest(noTLS bool, amount uint32) *http.Request
}

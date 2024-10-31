package customtls

//import (
//	"bufio"
//	"fmt"
//	tls "github.com/refraction-networking/utls"
//	"golang.org/x/net/http2"
//	"net"
//	"net/http"
//)

//func MakeUTLSConn(dial net.Conn, host string) (*tls.UConn, error) {
//	config := tls.Config{
//		ServerName:         host,
//		InsecureSkipVerify: true,
//	}
//
//	uTlsConn := tls.UClient(dial, &config, tls.HelloChrome_106_Shuffle)
//	//defer uTlsConn.Close()
//
//	err := uTlsConn.Handshake()
//	if err != nil {
//		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
//	}
//	return uTlsConn, nil
//}
//
//func HttpOverUTLSConn(conn net.Conn, req *http.Request, alpn string) (*http.Response, error) {
//	switch alpn {
//	case "h2":
//		req.Proto = "HTTP/2.0"
//		req.ProtoMajor = 2
//		req.ProtoMinor = 0
//
//		tr := http2.Transport{}
//		cConn, err := tr.NewClientConn(conn)
//		if err != nil {
//			return nil, err
//		}
//		return cConn.RoundTrip(req)
//
//	case "http/1.1", "":
//		req.Proto = "HTTP/1.1"
//		req.ProtoMajor = 1
//		req.ProtoMinor = 1
//
//		err := req.Write(conn)
//		if err != nil {
//			return nil, err
//		}
//		return http.ReadResponse(bufio.NewReader(conn), req)
//	default:
//		return nil, fmt.Errorf("unsupported ALPN: %v", alpn)
//	}
//
//}

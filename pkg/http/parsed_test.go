package http

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// countedProtocol is a stub config that remembers its link.
type countedProtocol struct {
	OrigLink string
	port     string
}

func (p *countedProtocol) Parse() error       { return nil }
func (p *countedProtocol) DetailsStr() string { return "" }
func (p *countedProtocol) GetLink() string    { return p.OrigLink }
func (p *countedProtocol) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{Protocol: "stub", Address: "127.0.0.1", Port: p.port, TLS: "none", OrigLink: p.OrigLink}
}

// countingCore counts CreateProtocol calls per link.
type countingCore struct {
	stubCore
	port  string
	mu    sync.Mutex
	calls map[string]int
}

func (c *countingCore) CreateProtocol(link string) (protocol.Protocol, error) {
	c.mu.Lock()
	c.calls[link]++
	c.mu.Unlock()
	if link == "panic://parser" {
		panic("parser exploded")
	}
	return &countedProtocol{OrigLink: link, port: c.port}, nil
}

func (c *countingCore) MakeHttpClient(ctx context.Context, p protocol.Protocol, d time.Duration) (*http.Client, protocol.Instance, error) {
	return c.stubCore.MakeHttpClient(ctx, p, d)
}

// Dedup, prescan and the test share one parse per link, and a finished
// test releases its parsed protocol.
func TestParseOncePipeline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	srv := gradeTestServer(t)
	cc := &countingCore{stubCore: stubCore{client: srv.Client()}, port: port, calls: map[string]int{}}
	links := []string{"stub://a", "stub://b", "stub://a", " stub://c ", "", "panic://parser"}

	// As cmd/http does: exact duplicates go before parsing, then semantic dedup
	// reuses the parse.
	unique, exact := DeduplicateLinks(links)
	parsed, removed := SemanticDeduplicateParsed(ParseLinks(cc, unique))
	removed += exact - 1 // DeduplicateLinks also counts the dropped empty line
	if removed != 1 || len(parsed) != 4 {
		t.Fatalf("dedup kept %d, removed %d", len(parsed), removed)
	}
	pre, err := RunPrescanParsed(context.Background(), parsed, PrescanOptions{Timeout: time.Second}, nil, nil)
	if err != nil || len(pre.ReachableParsed) != 4 {
		t.Fatalf("prescan: %+v, %v", pre, err)
	}

	e := newGradeExaminer(srv.Client(), []EndpointCheck{{URL: srv.URL + "/ok"}}, 1)
	e.Core = cc
	e.Logger = log.New(io.Discard, "", 0)
	ch := make(chan *Result, 8)
	NewTestManager(e, 2, false, nil).RunParsed(context.Background(), pre.ReachableParsed, ch, nil)
	close(ch)
	statuses := map[string]string{}
	for r := range ch {
		statuses[r.ConfigLink] = r.Status
	}
	if statuses["stub://a"] != StatusPassed || statuses["stub://c"] != StatusPassed || statuses["panic://parser"] != StatusBroken {
		t.Fatalf("statuses = %v", statuses)
	}

	for link, n := range cc.calls {
		if n != 1 {
			t.Errorf("%s parsed %d times, want once", link, n)
		}
	}
	for _, pl := range pre.ReachableParsed {
		if pl.Proto != nil {
			t.Errorf("%s still holds its parsed protocol after the test", pl.Link)
		}
	}
}

func TestParseLinkErrorsMatchExamineWording(t *testing.T) {
	cc := &countingCore{calls: map[string]int{}}
	if pl := ParseLink(cc, "  "); pl.Err == nil || pl.Err.Error() != "config link is empty" {
		t.Errorf("empty link: %v", pl.Err)
	}
	if pl := ParseLink(cc, "panic://parser"); pl.Err == nil || pl.Proto != nil {
		t.Errorf("panic not confined: %+v", pl)
	}
	e := newGradeExaminer(nil, nil, 1)
	e.Core = cc
	r, err := e.ExamineConfig(context.Background(), "panic://parser")
	if err == nil || r.Status != StatusBroken || r.FailureKind != FailConfig {
		t.Fatalf("result = %+v, err %v", r, err)
	}
}

package sysproxy

import (
	"errors"
	"strings"
	"testing"
)

type fakeExec struct {
	calls  []string
	output map[string]string
	fail   map[string]bool
}

func (f *fakeExec) run(name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	for k := range f.fail {
		if strings.Contains(call, k) {
			return []byte("boom"), errors.New("exit status 1")
		}
	}
	return []byte(f.output[call]), nil
}

func withFakeExec(t *testing.T, f *fakeExec) {
	oldOut, oldComb := execOutput, execCombined
	execOutput, execCombined = f.run, f.run
	t.Cleanup(func() { execOutput, execCombined = oldOut, oldComb })
}

func TestParseProxyInfo(t *testing.T) {
	data := map[string]string{}
	parseProxyInfo(data, "p:", "Enabled: No\nServer: proxy.corp\nPort: 3128\nAuthenticated Proxy Enabled: 0\n")
	if data["p:enabled"] != "No" || data["p:server"] != "proxy.corp" || data["p:port"] != "3128" {
		t.Fatalf("data = %v", data)
	}
}

func TestServiceHasIP(t *testing.T) {
	if !serviceHasIP("DHCP Configuration\nIP address: 192.168.1.5\nSubnet mask: 255.255.255.0\n") {
		t.Fatal("v4 service not active")
	}
	if !serviceHasIP("IP address: none\nIPv6 IP address: 2001:db8::5\n") {
		t.Fatal("v6-only service not active")
	}
	if serviceHasIP("IP address: none\nIPv6: Automatic\n") {
		t.Fatal("service without address reported active")
	}
}

// Restore keeps a configured-but-disabled proxy's server/port, and keeps
// going after a failure so other services are not left pointing at us.
func TestDarwinRestore(t *testing.T) {
	f := &fakeExec{fail: map[string]bool{"-setwebproxy Wi-Fi": true}}
	withFakeExec(t, f)
	prev := &Settings{Platform: "darwin", Data: map[string]string{
		"services":              "Wi-Fi|Ethernet",
		"svc:Wi-Fi:web:enabled": "Yes", "svc:Wi-Fi:web:server": "corp", "svc:Wi-Fi:web:port": "3128",
		"svc:Ethernet:socks:enabled": "No", "svc:Ethernet:socks:server": "old.socks", "svc:Ethernet:socks:port": "1080",
	}}
	err := (&darwinManager{}).Restore(prev)
	if err == nil || !strings.Contains(err.Error(), "-setwebproxy Wi-Fi corp 3128") {
		t.Fatalf("err = %v", err)
	}
	joined := strings.Join(f.calls, "\n")
	for _, want := range []string{
		"networksetup -setsocksfirewallproxy Ethernet old.socks 1080",
		"networksetup -setsocksfirewallproxystate Ethernet off",
		"networksetup -setwebproxystate Wi-Fi on",
		"networksetup -setsecurewebproxystate Ethernet off",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing call %q in:\n%s", want, joined)
		}
	}
}

// Set configures the services Get recorded, so Restore undoes exactly them.
func TestDarwinSetUsesRecordedServices(t *testing.T) {
	f := &fakeExec{output: map[string]string{}}
	withFakeExec(t, f)
	m := &darwinManager{services: []string{"USB LAN"}}
	if err := m.Set("127.0.0.1", "9999"); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "-listallnetworkservices") {
			t.Fatal("Set re-listed services")
		}
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), "-setsocksfirewallproxy USB LAN 127.0.0.1 9999") {
		t.Fatalf("calls = %v", f.calls)
	}
}

package xray

import "testing"

func TestShadowSocks_Parse(t *testing.T) {
	var ss Shadowsocks
	err := ss.Parse("ss://YWVzLTI1Ni1nY206RXhhbXBsZUAxMjM0@example.com:443#exa")
	if err != nil {
		t.Errorf("Error when parsing: %v", err)
	}
	t.Logf("%s\n", ss.DetailsStr())
}

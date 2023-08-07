package vmess

import (
	"encoding/json"
	"fmt"
	"strings"
	"xray-knife/utils"
)

type Vmess struct {
	Version  string      `json:"v"`
	Address  string      `json:"add"`
	Aid      interface{} `json:"aid"`
	Host     string      `json:"host"`
	ID       string      `json:"id"`
	Network  string      `json:"net"`
	Path     string      `json:"path"`
	Port     interface{} `json:"port"`
	Remark   string      `json:"ps"` // Config's name
	TLS      string      `json:"tls"`
	SNI      string      `json:"sni"`  // Server name indication
	ALPN     string      `json:"alpn"` // Application-Layer Protocol Negotiation
	Type     string      `json:"type"` // Used for HTTP Obfuscation
	OrigLink string      `json:"-"`    // Original link
}

func NewVmess(config string) (*Vmess, error) {
	if !strings.HasPrefix(config, "vmess://") {
		return nil, fmt.Errorf("vmess unreconized: %s", config)
	}

	b64 := config[8:]
	decoded, err := utils.Base64Decode(b64)
	if err != nil {
		return nil, err
	}
	fmt.Println(string(decoded))

	v := &Vmess{}
	if err := json.Unmarshal(decoded, v); err != nil {
		return nil, err
	}
	v.OrigLink = config

	return v, nil
}

func ParseVmess(vmess string) (*Vmess, error) {
	var config *Vmess
	if res, err := NewVmess(vmess); err == nil {
		config = res
	} else {
		return nil, fmt.Errorf("%v", err)
	}
	return config, nil
}

package xray

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/xtls/xray-core/infra/conf"
)

func NewWireguard() Protocol {
	return &Wireguard{}
}

func (w *Wireguard) Name() string {
	return "wireguard"
}

func (w *Wireguard) Parse(configLink string) error {
	if !strings.HasPrefix(configLink, wireguardIdentifier) {
		return fmt.Errorf("wireguard unreconized: %s", configLink)
	}

	uri, err := url.Parse(configLink)
	if err != nil {
		return err
	}

	unescapedSecretKey, err0 := url.PathUnescape(uri.User.String())
	if err0 != nil {
		return err0
	}

	w.SecretKey = unescapedSecretKey

	w.Endpoint = uri.Host

	// Get the type of the struct
	t := reflect.TypeOf(*w)

	// Get the number of fields in the struct
	numFields := t.NumField()

	// Iterate over each field of the struct
	for i := 0; i < numFields; i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")

		// If the query value exists for the field, set it
		if values, ok := uri.Query()[tag]; ok {
			value := values[0]
			v := reflect.ValueOf(w).Elem().FieldByName(field.Name)

			switch v.Type().String() {
			case "string":
				v.SetString(value)
			case "int32":
				var intValue int
				fmt.Sscanf(value, "%d", &intValue)
				v.SetInt(int64(intValue))

			}
		}
	}

	w.Remark, err = url.PathUnescape(uri.Fragment)
	if err != nil {
		w.Remark = uri.Fragment
	}

	return nil
}

func (w *Wireguard) DetailsStr() string {
	return detailsToStr(w.details())
}

func (w *Wireguard) DetailsMap() map[string]string {
	return detailsToMap(w.details())
}

func (w *Wireguard) details() [][2]string {
	return [][2]string{
		{"Protocol", w.Name()},
		{"Remark", w.Remark},
		{"Endpoint", w.Endpoint},
		{"MTU", fmt.Sprintf("%d", w.Mtu)},
		{"Local Addresses", w.LocalAddress},
		{"Public Key", w.PublicKey},
		{"Secret Key", w.SecretKey},
	}
}

func (w *Wireguard) ConvertToGeneralConfig() GeneralConfig {
	var g GeneralConfig
	g.Protocol = w.Name()
	g.Address = w.Endpoint

	return g
}

func (w *Wireguard) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	out := &conf.OutboundDetourConfig{}
	out.Tag = "proxy"
	out.Protocol = w.Name()

	// c := conf.WireGuardConfig{
	//	IsClient:   true,
	//	KernelMode: nil,
	//	SecretKey:  w.SecretKey,
	//	Address:    strings.Split(w.LocalAddress, ","),
	//	Peers: []*conf.WireGuardPeerConfig{
	//		{
	//			PublicKey:    w.PublicKey,
	//			PreSharedKey: "",
	//			Endpoint:     w.Endpoint,
	//			KeepAlive:    0,
	//			AllowedIPs:   nil,
	//		},
	//	},
	//	MTU:            w.Mtu,
	//	DomainStrategy: "ForceIPv6v4",
	// }

	oset := json.RawMessage([]byte(fmt.Sprintf(`{
  "secretKey": "%s",
  "address": ["%s", "%s"],
  "peers": [
    {
      "endpoint": "%s",
      "publicKey": "%s"
    }
  ],
  "mtu": %d
}
`, w.SecretKey, strings.Split(w.LocalAddress, ",")[0], strings.Split(w.LocalAddress, ",")[1], w.Endpoint, w.PublicKey, w.Mtu,
	)))
	out.Settings = &oset

	return out, nil
}

func (w *Wireguard) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	return nil, nil
}

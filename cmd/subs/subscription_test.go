package subs

import "testing"

func TestSubscription_FetchAll(t *testing.T) {
	s := Subscription{Url: "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/reality"}
	_, err := s.FetchAll()
	if err != nil {
		t.Errorf("FetchAll error: %v", err)
	}
	t.Logf("First and Second config: \n%s\n%s", s.ConfigLinks[0], s.ConfigLinks[1])
	t.Logf("Total configs: %d", len(s.ConfigLinks))
}

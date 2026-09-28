package sysproxy

import (
	"errors"
	"testing"
)

// Without a supported desktop nothing system-wide changes; Set must say so
// instead of reporting success.
func TestLinuxUnknownDesktopIsManual(t *testing.T) {
	t.Setenv("XRAY_KNIFE_HOME", t.TempDir())
	err := (&linuxManager{de: deUnknown}).Set("127.0.0.1", "9999")
	var manual *ManualConfigError
	if !errors.As(err, &manual) || manual.Path == "" {
		t.Fatalf("err = %v", err)
	}
}

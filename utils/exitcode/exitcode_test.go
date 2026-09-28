package exitcode

import (
	"errors"
	"fmt"
	"testing"
)

func TestOf(t *testing.T) {
	base := errors.New("boom")
	err := fmt.Errorf("wrapped: %w", New(NothingPassed, base))
	code, ok := Of(err)
	if !ok || code != NothingPassed {
		t.Fatalf("Of = %d, %v", code, ok)
	}
	if !errors.Is(err, base) {
		t.Fatal("ExitError does not unwrap")
	}
	if _, ok := Of(base); ok {
		t.Fatal("plain error reported a code")
	}
	if !IsSilent(Silent(Error)) || IsSilent(New(Error, base)) {
		t.Fatal("IsSilent")
	}
	if Silent(3).Error() != "exit status 3" {
		t.Fatal("silent error text")
	}
}

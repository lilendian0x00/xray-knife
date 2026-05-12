package database

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"time"
)

// NullTime is a nullable time that tolerates the mixture of formats
// modernc.org/sqlite may return: a parsed time.Time, an RFC-style
// "2006-01-02 15:04:05.999999999-07:00" string (the _time_format=sqlite
// output), bare SQLite "YYYY-MM-DD HH:MM:SS" text, or the legacy
// time.Time.String() form "... +HHMM ABBR m=+..." that older rows used.
type NullTime struct {
	Time  time.Time
	Valid bool
}

// scanTimeFormats covers what we may encounter on disk. Order matters:
// most specific first.
var scanTimeFormats = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02T15:04:05.999999999-07:00",
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04",
	"2006-01-02T15:04",
	"2006-01-02",
}

func parseTimeLoose(s string) (time.Time, error) {
	// Legacy time.Time.String() form: "...-0700 ABBR m=+..."
	if i := strings.Index(s, " m="); i > 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if t, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", s); err == nil {
		return t, nil
	}
	trimmed := strings.TrimSuffix(s, "Z")
	for _, f := range scanTimeFormats {
		if t, err := time.Parse(f, trimmed); err == nil {
			return t, nil
		}
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q", s)
}

func (n *NullTime) Scan(value any) error {
	if value == nil {
		n.Time, n.Valid = time.Time{}, false
		return nil
	}
	switch v := value.(type) {
	case time.Time:
		n.Time, n.Valid = v, true
		return nil
	case string:
		t, err := parseTimeLoose(v)
		if err != nil {
			return err
		}
		n.Time, n.Valid = t, true
		return nil
	case []byte:
		t, err := parseTimeLoose(string(v))
		if err != nil {
			return err
		}
		n.Time, n.Valid = t, true
		return nil
	}
	return fmt.Errorf("NullTime: unsupported scan type %T", value)
}

func (n NullTime) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	return n.Time.UTC(), nil
}

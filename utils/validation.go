package utils

import "strings"

func IsValidHostOrSNI(value string) bool {
	return !strings.ContainsAny(value, "[]()")
}

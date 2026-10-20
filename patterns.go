package mwanachamaauth

import (
	"regexp"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

var e164Pattern = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

func isE164(s string) bool { return e164Pattern.MatchString(s) }

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isSHA256Hex(s string) bool { return sha256HexPattern.MatchString(s) }

func isEmailAddress(s string) bool { return s == models.Normalize(s) && models.ValidEmail(s) }

var patterns = map[string]func(string) bool{
	"e164":          isE164,
	"email_address": isEmailAddress,
	"sha256_hex":    isSHA256Hex,
}

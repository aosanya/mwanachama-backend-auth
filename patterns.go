package mwanachamaauth

import (
	"regexp"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

var e164Pattern = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

func isE164(s string) bool { return e164Pattern.MatchString(s) }

func isEmailAddress(s string) bool { return s == models.Normalize(s) && models.ValidEmail(s) }

var patterns = map[string]func(string) bool{
	"e164":          isE164,
	"email_address": isEmailAddress,
}

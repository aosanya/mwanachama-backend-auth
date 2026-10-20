package mwanachamaauth_test

import (
	"testing"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

func TestDescribeUserAgentNamesTheBrowserAndTheSystem(t *testing.T) {
	cases := map[string]string{
		firefoxOnLinux: "Firefox on Linux",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36":                        "Chrome on Windows",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0":          "Edge on Windows",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15":                  "Safari on macOS",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0 Mobile/15E148 Safari/604.1": "Chrome on iOS",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36":                  "Chrome on Android",
		"curl/8.5.0": "",
		"":           "",
	}
	for ua, want := range cases {
		if got := mwanachamaauth.DescribeUserAgent(ua); got != want {
			t.Errorf("DescribeUserAgent(%q) = %q, want %q", ua, got, want)
		}
	}
}

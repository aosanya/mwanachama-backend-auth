package mwanachamaauth_test

import (
	"testing"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

func TestClassifyUserAgentTellsAPhoneFromAComputerAndAnAppFromABrowser(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want models.DeviceClass
	}{
		{"chrome on an android phone", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
			models.DeviceClass{Form: models.DeviceFormPhone, Client: models.DeviceClientBrowser, Description: "Chrome on Android"}},
		{"safari on an iphone", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
			models.DeviceClass{Form: models.DeviceFormPhone, Client: models.DeviceClientBrowser, Description: "Safari on iOS"}},
		{"safari on an ipad", "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			models.DeviceClass{Form: models.DeviceFormTablet, Client: models.DeviceClientBrowser, Description: "Safari on iPadOS"}},
		{"chrome on an android tablet", "Mozilla/5.0 (Linux; Android 13; SM-X200) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
			models.DeviceClass{Form: models.DeviceFormTablet, Client: models.DeviceClientBrowser, Description: "Chrome on Android"}},
		{"an android web view inside an installed app", "Mozilla/5.0 (Linux; Android 14; Pixel 8; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/129.0.0.0 Mobile Safari/537.36",
			models.DeviceClass{Form: models.DeviceFormPhone, Client: models.DeviceClientApp, Description: "Chrome on Android"}},
		{"a flutter app", "Dart/3.5 (dart:io)",
			models.DeviceClass{Form: models.DeviceFormUnknown, Client: models.DeviceClientApp, Description: ""}},
		{"an ios app on the system networking stack", "MemberApp/12 CFNetwork/1494.0.7 Darwin/23.4.0",
			models.DeviceClass{Form: models.DeviceFormUnknown, Client: models.DeviceClientApp, Description: ""}},
		{"firefox on linux", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
			models.DeviceClass{Form: models.DeviceFormComputer, Client: models.DeviceClientBrowser, Description: "Firefox on Linux"}},
		{"edge on windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
			models.DeviceClass{Form: models.DeviceFormComputer, Client: models.DeviceClientBrowser, Description: "Edge on Windows"}},
		{"safari on a mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
			models.DeviceClass{Form: models.DeviceFormComputer, Client: models.DeviceClientBrowser, Description: "Safari on macOS"}},
		{"chrome on a chromebook", "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
			models.DeviceClass{Form: models.DeviceFormComputer, Client: models.DeviceClientBrowser, Description: "Chrome on ChromeOS"}},
		{"a command-line client", "curl/8.5.0", models.DeviceClass{}},
		{"no user agent at all", "", models.DeviceClass{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mwanachamaauth.ClassifyUserAgent(c.ua); got != c.want {
				t.Errorf("ClassifyUserAgent(%q) = %+v, want %+v", c.ua, got, c.want)
			}
		})
	}
}

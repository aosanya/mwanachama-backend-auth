package mwanachamaauth

import "strings"

type agentMark struct {
	token string
	name  string
}

var browserMarks = []agentMark{
	{"Edg/", "Edge"},
	{"EdgA/", "Edge"},
	{"EdgiOS/", "Edge"},
	{"OPR/", "Opera"},
	{"SamsungBrowser/", "Samsung Internet"},
	{"FxiOS/", "Firefox"},
	{"Firefox/", "Firefox"},
	{"CriOS/", "Chrome"},
	{"Chrome/", "Chrome"},
	{"Safari/", "Safari"},
}

var systemMarks = []agentMark{
	{"iPhone", "iOS"},
	{"iPad", "iPadOS"},
	{"Android", "Android"},
	{"CrOS", "ChromeOS"},
	{"Windows", "Windows"},
	{"Mac OS X", "macOS"},
	{"Macintosh", "macOS"},
	{"Linux", "Linux"},
}

func firstMark(ua string, marks []agentMark) string {
	for _, m := range marks {
		if strings.Contains(ua, m.token) {
			return m.name
		}
	}
	return ""
}

func DescribeUserAgent(ua string) string {
	browser := firstMark(ua, browserMarks)
	system := firstMark(ua, systemMarks)
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	default:
		return system
	}
}

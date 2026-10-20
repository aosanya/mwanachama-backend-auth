package mwanachamaauth

import (
	"strings"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

var installedAppMarks = []string{"; wv)", "Dart/", "okhttp/", "CFNetwork/", "Expo/", "ReactNative"}

var tabletMarks = []string{"iPad", "Tablet", "Kindle", "Silk/"}

var phoneMarks = []string{"iPhone", "iPod", "Windows Phone", "Mobile"}

var computerMarks = []string{"Windows NT", "Macintosh", "Mac OS X", "CrOS", "X11", "Linux"}

func containsAny(ua string, marks []string) bool {
	for _, m := range marks {
		if strings.Contains(ua, m) {
			return true
		}
	}
	return false
}

func deviceForm(ua string) models.DeviceForm {
	switch {
	case containsAny(ua, tabletMarks):
		return models.DeviceFormTablet
	case strings.Contains(ua, "Android") && !strings.Contains(ua, "Mobile"):
		return models.DeviceFormTablet
	case containsAny(ua, phoneMarks), strings.Contains(ua, "Android"):
		return models.DeviceFormPhone
	case containsAny(ua, computerMarks):
		return models.DeviceFormComputer
	default:
		return models.DeviceFormUnknown
	}
}

func deviceClient(ua string) models.DeviceClient {
	switch {
	case containsAny(ua, installedAppMarks):
		return models.DeviceClientApp
	case firstMark(ua, browserMarks) != "":
		return models.DeviceClientBrowser
	default:
		return models.DeviceClientUnknown
	}
}

func ClassifyUserAgent(ua string) models.DeviceClass {
	return models.DeviceClass{
		Form:        deviceForm(ua),
		Client:      deviceClient(ua),
		Description: DescribeUserAgent(ua),
	}
}

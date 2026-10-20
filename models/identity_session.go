package models

import (
	"errors"
	"time"
)

var ErrIdentitySessionFunctionsMissing = errors.New("identity sessions: the identity project has no session functions this role may call")

type DeviceForm string

const (
	DeviceFormPhone    DeviceForm = "phone"
	DeviceFormTablet   DeviceForm = "tablet"
	DeviceFormComputer DeviceForm = "computer"
	DeviceFormUnknown  DeviceForm = ""
)

type DeviceClient string

const (
	DeviceClientApp     DeviceClient = "app"
	DeviceClientBrowser DeviceClient = "browser"
	DeviceClientUnknown DeviceClient = ""
)

type DeviceClass struct {
	Form        DeviceForm   `json:"form"`
	Client      DeviceClient `json:"client"`
	Description string       `json:"description"`
}

type IdentitySession struct {
	ID              string      `json:"id"`
	SubjectID       string      `json:"subject_id"`
	Device          DeviceClass `json:"device"`
	StartedAt       time.Time   `json:"started_at"`
	LastRefreshedAt time.Time   `json:"last_refreshed_at"`
}

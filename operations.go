package mwanachamaauth

import (
	_ "embed"
	"sync"

	"github.com/aosanya/mwanachama-backend-shared/dispatch"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

//go:embed auth.operations.json
var operationsJSON []byte

func Operations() []byte { return operationsJSON }

var loadOperations = sync.OnceValues(func() (*dispatch.Spec, error) {
	return dispatch.Parse(operationsJSON)
})

func OperationSpec() (*dispatch.Spec, error) { return loadOperations() }

func Sentinels() map[string]error {
	return map[string]error{
		"ErrAuthNotFound":              models.ErrAuthNotFound,
		"ErrAuthChallengeExpired":      models.ErrAuthChallengeExpired,
		"ErrAuthDeviceSignedOut":       models.ErrAuthDeviceSignedOut,
		"ErrAuthSignOutReasonRequired": models.ErrAuthSignOutReasonRequired,
		"ErrOperatorNotFound":          models.ErrOperatorNotFound,
		"ErrOperatorDisabled":          models.ErrOperatorDisabled,
		"ErrOperatorEmailTaken":        models.ErrOperatorEmailTaken,
		"ErrPasswordTooShort":          ErrPasswordTooShort,
		"ErrVerificationNotFound":      models.ErrVerificationNotFound,
		"ErrPhoneSaltNotFound":         models.ErrPhoneSaltNotFound,
		"ErrPhoneSaltAlreadyLive":      models.ErrPhoneSaltAlreadyLive,
		"ErrPhoneSaltRetired":          models.ErrPhoneSaltRetired,
		"ErrPhoneSaltNoActor":          models.ErrPhoneSaltNoActor,
	}
}

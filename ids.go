package mwanachamaauth

import (
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	seqDevice     = "auth_device_seq"
	seqChallenge  = "auth_challenge_seq"
	seqCredential = "operator_credential_seq"
)

var seqNames = []string{seqDevice, seqChallenge, seqCredential}

func mintID(tx *gorm.DB, prefix, seq string) (string, error) {
	if tx.Dialector.Name() == "postgres" {
		var n int64
		if err := tx.Raw("SELECT nextval(?::regclass)", seq).Scan(&n).Error; err != nil {
			return "", fmt.Errorf("mintID: %s: %w", seq, err)
		}
		return fmt.Sprintf("%s-%d", prefix, n), nil
	}
	return prefix + "-" + uuid.NewString(), nil
}

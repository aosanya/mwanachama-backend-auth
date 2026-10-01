package mwanachamaauth

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

var legacyGateway = spec.Legacy{
	Tables: map[string]string{
		roleDevice:            "auth_device",
		roleChallenge:         "auth_challenge",
		rolePhoneBinding:      "auth_phone",
		rolePhoneAttempt:      "auth_phone_attempt",
		roleCredential:        "operator_credential",
		roleCredentialAttempt: "operator_attempt",
		roleVerification:      "verification",
		roleSalt:              "phone_salt",
	},
	Columns: map[string]string{
		"member_id":       "subject_id",
		"failed_attempts": "failed",
	},
	IndexPrefixes: []string{"auth_", "operator_", "phone_salt_", "verification_", "idx_"},
}

var legacyPrefixed = spec.Legacy{
	Tables: map[string]string{
		roleDevice:            "auth_device",
		roleChallenge:         "auth_challenge",
		rolePhoneBinding:      "auth_phone",
		rolePhoneAttempt:      "auth_phone_attempt",
		roleCredential:        "auth_operator_credential",
		roleCredentialAttempt: "auth_operator_attempt",
		roleVerification:      "auth_verification",
		roleSalt:              "auth_phone_salt",
	},
	Columns:       legacyGateway.Columns,
	IndexPrefixes: legacyGateway.IndexPrefixes,
}

func LegacyNames() []spec.Legacy { return []spec.Legacy{legacyGateway, legacyPrefixed} }

func Provision(db *gorm.DB, s *spec.Spec) error {
	for _, l := range LegacyNames() {
		if err := spec.AdoptLegacy(db, s, l); err != nil {
			return err
		}
	}
	if err := spec.Migrate(db, s); err != nil {
		return err
	}
	stored := func(o spec.Object, table, column string) string {
		return spec.UnsetClause(db, o, table, column)
	}
	for _, stmt := range provisionStatements(s, db.Dialector.Name(), stored) {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("auth: provision: %w", err)
		}
	}
	return retireStaleSignOutReason(db, s)
}

func ProvisionStatements(s *spec.Spec, dialect string) []string {
	declared := func(o spec.Object, table, column string) string {
		return spec.UnsetSQL(column, spec.DeclaresTextualColumn(o, column, dialect))
	}
	return provisionStatements(s, dialect, declared)
}

type unsetClause func(o spec.Object, table, column string) string

func provisionStatements(s *spec.Spec, dialect string, unset unsetClause) []string {
	var out []string
	if dialect == "postgres" {
		for _, seq := range seqNames {
			out = append(out, "CREATE SEQUENCE IF NOT EXISTS "+seq)
		}
	}
	if o, ok := s.ByRole(roleSalt); ok {
		table := s.TableFor(o)
		live := unset(o, table, columnName("RetiredAt"))
		out = append(out, fmt.Sprintf(
			`CREATE UNIQUE INDEX IF NOT EXISTS %s_one_live ON %s (%s) WHERE %s`,
			table, table, live, live,
		))
	}
	return out
}

func retireStaleSignOutReason(db *gorm.DB, s *spec.Spec) error {
	o, ok := s.ByRole(roleDevice)
	if !ok {
		return nil
	}
	table := s.TableFor(o)
	if !db.Migrator().HasTable(table) {
		return nil
	}
	column := columnName("SignedOutBy")
	stmt := fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?", table, column, column)
	if err := db.Exec(stmt, string(models.SignOutBySelf), legacySignOutBySelf).Error; err != nil {
		return fmt.Errorf("auth: retireStaleSignOutReason: %w", err)
	}
	return nil
}

const legacySignOutBySelf = "member"

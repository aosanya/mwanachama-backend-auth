// Package gormstore holds every GORM-specific piece of this repo: row
// structs, their conversion to/from the domain types in
// mwanachama-backend-auth/models, and table migration. Nothing outside this
// package (and the root mwanachama-backend-auth package's *_impl.go files,
// which call it) needs to know GORM exists — mirrors
// mwanachama-backend-actor's and mwanachama-backend-comm's identical
// gormstore/ split.
package gormstore

import (
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TableNames configures which physical tables a store reads and writes. The
// eight names below are the gateway's own original production table names —
// see DefaultTableNames — kept fixed rather than instance-scoped the way
// actor's member/chapter tables were, since all eight already exist in the
// gateway's Postgres under these exact names and reusing them means no data
// migration is needed if this repo ever points at the same database. The
// struct still exists, rather than hard-coding the names, so a test can
// migrate a differently-named scratch set without colliding with a
// concurrent test run.
type TableNames struct {
	AuthDevices       string
	AuthChallenges    string
	AuthPhones        string
	AuthPhoneAttempts string

	OperatorCredentials string
	OperatorAttempts    string

	Verifications string

	PhoneSalts string
}

// DefaultTableNames returns the eight real production table names the
// archived gateway migrations created — auth_device, auth_challenge,
// auth_phone, auth_phone_attempt, operator_credential, operator_attempt,
// verification and phone_salt (migrations 000007, 000009, 000018, 000020,
// 000029, 000048 in mwanachama-backend-api-gateway's
// internal/store/postgres/migrations_archive).
func DefaultTableNames() TableNames {
	return TableNames{
		AuthDevices:       "auth_device",
		AuthChallenges:    "auth_challenge",
		AuthPhones:        "auth_phone",
		AuthPhoneAttempts: "auth_phone_attempt",

		OperatorCredentials: "operator_credential",
		OperatorAttempts:    "operator_attempt",

		Verifications: "verification",

		PhoneSalts: "phone_salt",
	}
}

// Migrate creates or updates the eight tables t names, via GORM's AutoMigrate
// scoped to each table name in turn, plus the Postgres SEQUENCEs the
// id-minting BeforeCreate hooks below read from (see mintID) and the
// constraints/indexes AutoMigrate cannot express from a Go struct tag alone.
// Callers run this once at startup (or in test setup) before constructing a
// store with the same db and t.
func Migrate(db *gorm.DB, t TableNames) error {
	if db.Dialector.Name() == "postgres" {
		if err := createSequences(db); err != nil {
			return err
		}
	}
	migrations := []struct {
		table string
		row   any
	}{
		{t.AuthDevices, &DeviceRow{}},
		{t.AuthChallenges, &ChallengeRow{}},
		{t.AuthPhones, &AuthPhoneRow{}},
		{t.AuthPhoneAttempts, &PhoneAttemptRow{}},
		{t.OperatorCredentials, &CredentialRow{}},
		{t.OperatorAttempts, &OperatorAttemptRow{}},
		{t.Verifications, &VerificationRow{}},
		{t.PhoneSalts, &SaltRow{}},
	}
	for _, m := range migrations {
		if err := db.Table(m.table).AutoMigrate(m.row); err != nil {
			return fmt.Errorf("gormstore.Migrate: %s: %w", m.table, err)
		}
	}
	if err := syncPhoneSaltOneLiveIndex(db, t.PhoneSalts); err != nil {
		return err
	}
	return nil
}

// syncPhoneSaltOneLiveIndex creates the partial unique index AutoMigrate
// cannot express from a struct tag alone: at most one live (non-retired) salt
// per deployment — the archived migration 000018_phone_salt's
// phone_salt_one_live. Two live salts would be two answers to "which key do I
// hash under", and the loser's hashes would match nothing while looking
// perfectly well-formed. Partial-index syntax is identical on Postgres and
// sqlite, so one statement covers both dialects this package supports.
func syncPhoneSaltOneLiveIndex(db *gorm.DB, table string) error {
	stmt := fmt.Sprintf(
		`CREATE UNIQUE INDEX IF NOT EXISTS %s_one_live ON %s ((retired_at IS NULL)) WHERE retired_at IS NULL`,
		table, table,
	)
	if err := db.Exec(stmt).Error; err != nil {
		return fmt.Errorf("syncPhoneSaltOneLiveIndex: %w", err)
	}
	return nil
}

// seqNames is every Postgres SEQUENCE an id-minting BeforeCreate hook reads
// from (see mintID) — the same three sequences the archived migrations
// declared (auth_device_seq, auth_challenge_seq, operator_credential_seq),
// carried over unchanged. auth_phone, auth_phone_attempt, operator_attempt,
// verification and phone_salt mint no id of their own: their primary key is
// a caller-supplied natural key (phone, email, member_id, an explicit salt
// version), not a sequence.
var seqNames = []string{
	"auth_device_seq",
	"auth_challenge_seq",
	"operator_credential_seq",
}

func createSequences(db *gorm.DB) error {
	for _, seq := range seqNames {
		if err := db.Exec("CREATE SEQUENCE IF NOT EXISTS " + seq).Error; err != nil {
			return fmt.Errorf("gormstore.Migrate: %s: %w", seq, err)
		}
	}
	return nil
}

// mintID produces a human-readable, prefix-and-number id the way the
// production Postgres schema always has (e.g. "device-1042"), by reading the
// next value of a server-side SEQUENCE on Postgres.
//
// sqlite (this repo's fast-test dialect only) has no SEQUENCE, so it falls
// back to a uuid-suffixed id with the same prefix. Every behavioural
// assertion this repo's tests make (non-empty, unique) holds under either
// dialect; only the exact digits after the prefix differ, which nothing
// depends on.
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

// StringToNullable maps an empty string onto a nil *string, matching actor's
// and comm's identical helper — the archived gateway schema stores an absent
// optional string as SQL NULL, not as "".
func StringToNullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// NullableToString is StringToNullable's inverse.
func NullableToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

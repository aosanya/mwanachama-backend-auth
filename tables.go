package mwanachamaauth

// tables.go wraps gormstore.TableNames/DefaultTableNames/Migrate, mirroring
// mwanachama-backend-actor's and mwanachama-backend-comm's identical root
// package wrappers — a caller of this repo never needs to import
// mwanachama-backend-auth/gormstore directly.

import (
	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-auth/gormstore"
)

// TableNames configures which physical tables the *Store types in this
// package read and write.
type TableNames = gormstore.TableNames

// DefaultTableNames returns this repo's eight real production table names —
// see gormstore.DefaultTableNames.
func DefaultTableNames() TableNames { return gormstore.DefaultTableNames() }

// Migrate creates or updates every table t names. Callers run this once at
// startup (or in test setup) before constructing any of this package's
// *Store types with the same db and t.
func Migrate(db *gorm.DB, t TableNames) error { return gormstore.Migrate(db, t) }

# Adopted column types, and the "absent" predicate

`spec.Migrate` is `create table if not exists`. It never alters a table it
finds, so a table reached through `spec.AdoptLegacy` keeps **every column type
the old hand-written SQL gave it**, forever. The declaration describes what a
*fresh* database gets; on an adopted one it is a description of the name and
the nullability, not of the type.

That is the state of `mwanachama-wakala-api`'s database. All eight auth tables
there were renamed in from the retired api-gateway, so they carry the
gateway's types:

| column | adopted type | `auth.blueprint.json` says |
| --- | --- | --- |
| `salt.retired_at` | `timestamp with time zone` | `timestamp` → emitted as `text` |
| `device.signed_out_at` | `timestamp with time zone` | `timestamp` → emitted as `text` |
| `credential.disabled_at` | `timestamp with time zone` | `timestamp` → emitted as `text` |
| `phone_attempt.failed` | `bigint` | `int` → emitted as `bigint` |

`spec.Migrate` maps `timestamp` to `text` so the unit tests can run on SQLite,
which is why the three nullable instants disagree and the integers do not.

## Why that broke the "absent" predicate

The three nullable columns are the ones whose absence differs from their zero,
so every read of a live row tests for absence. The predicate used to be a
constant string:

```go
func unsetText(column string) string {
	return "(" + column + " IS NULL OR " + column + " = '')"
}
```

The `= ''` half is there because a non-nullable text column declared without a
`nullable` flag gets `default ''`, so on a fresh database "absent" really can
be the empty string. Against an adopted `timestamptz` column, Postgres refuses
to coerce `''` at all:

```
ERROR: invalid input syntax for type timestamp with time zone: "" (SQLSTATE 22007)
```

That failed at four sites — the one-live-salt index in `Provision`, plus
`PhoneSaltStore.Retire`, `PhoneSaltStore.liveRecord`, `AuthStore
.SignOutOtherDevices` and `OperatorStore.Disable`. SQLite never caught it
because SQLite compares across types without complaint, and every test here
runs on a table `spec.Migrate` created, where the column really is text.

## The predicate asks the database

`spec.ColumnIsTextual` reads the column's real type —
`information_schema.columns` on Postgres, `pragma_table_info` on SQLite — and
`spec.UnsetSQL` emits the matching half:

| real column type | predicate |
| --- | --- |
| `text`, `varchar`, `char` | `(c IS NULL OR c = '')` |
| anything else | `(c IS NULL)` |

`specstore.Store.Unset(role, field)` is the call sites' entry point. It caches
per table and column, so the introspection is one query per column for the
life of the store, not one per request. `spec.UnsetClause` falls back to
`spec.DeclaresTextualColumn` — the declared type — when the database will not
say, which is the case a unit test on a table that does not exist yet hits.

`Provision` cannot use the `Store` method, because it runs before any store
exists, so it passes `spec.UnsetClause` into `provisionStatements` directly.
`ProvisionStatements`, which `cmd/ddl` prints and which has no database, keeps
using the declared type — correct, because what it prints is the DDL for a
fresh database.

## What this does not fix

The type drift itself. The declaration and an adopted database still disagree,
and anything else that assumes the emitted type will meet the same wall. The
alternative — having `AdoptLegacy` alter every adopted column to its declared
type — was considered and not taken: it rewrites live data and changes the
engine's contract for every repo that adopts, which is a decision of its own
rather than part of this fix.

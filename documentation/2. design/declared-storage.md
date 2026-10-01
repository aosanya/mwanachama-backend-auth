# Declared storage

The eight objects this module stores are declared in
[`auth.blueprint.json`](../../auth.blueprint.json), not written as Go row
structs. `gormstore/` and `tables.go` are gone. The engine is
`mwanachama-backend-shared`'s `spec` and `specstore`; the org-wide reasoning
is `developer/documentation/2. design/architecture-spec-driven-modules.md`.

## The roles

| Role | What it is |
| --- | --- |
| `device` | A client install bound to a subject, which proves itself by signing a nonce |
| `challenge` | A short-lived secret proving control of a device or a number |
| `phone_attempt` | One number's consecutive-wrong-code state |
| `phone_binding` | The standing link from a number to the subject it reaches |
| `credential` | An email-and-password credential for an operator console |
| `credential_attempt` | One address's consecutive-wrong-password state |
| `verification` | A subject's standing as checked by a reviewer |
| `salt` | One version of the key phone numbers are hashed under |

Two domains are shipped: `auth.platform.json`, which is the one in
production, and `auth.clinic.json`, which nobody has provisioned. The second
is the point — a shipped example that is also live config stops being a test
of anything. It also declares a `consent` object of its own, with no role, to
show a domain adding a table rather than asking the module for a field.

## The three naming decisions

**`MemberID` became `SubjectID`,** on five objects. "Member" is a
civic-society word; a clinic has patients and a library has readers. This
module records subjects.

**The stored sign-out reason `"member"` became `"self"`.** This is the worst
kind of domain word, because a stored enum value outlives a rename: the Go
constant is corrected in one commit and every row written before it still
says the old word. It is the only part of the rename that needs existing rows
rewritten rather than only columns renamed, and `Provision` does it.

**The wire names did not move.** `json:"member_id"` and the `/members/`
path segments are the HTTP contract already published, so they stay while the
column underneath becomes `subject_id`. `domain_agnostic_test.go` covers
identifiers, stored enum values and action ids, and says in its own body that
tags and paths are deliberately excluded.

`phone`, `device`, `operator` and `verification` all pass the test as they
stand: a clinic, a library and a union would each recognise them.

## Two carriers are not the models type

Six roles are carried by their `models` type. Two are not, and this is
deliberate:

- `credentialRecord` holds `password_hash`, which
  `models.OperatorCredential` does not have.
- `saltRecord` holds `secret`, which `models.Salt` does not have.

The standard's own answer for a stored secret is to put it on the model as
`json:"-"`, the way catalog carries `ShareLink.KeyHash`. That is a **hash**;
`Salt.Secret` is **live key material**, and this repo's `CLAUDE.md` calls its
absence from `models.Salt` a load-bearing security property. An unexported
carrier keeps both: the column is declared and written by the codec, and the
raw key is never on a type an API response is built from. **This is an open
question for the owner, not a settled decision** — see the board.

## `nullable` is exactly where the Go field is a pointer

`specstore` refuses a nullable column carried by a plain value, and a pointer
on a column nobody declared nullable. That resolved cleanly: the only three
nullable columns are `device.signed_out_at`, `credential.disabled_at` and
`salt.retired_at` — the three whose model comments already explain that a
zero instant reads as a real date and is not one.

Everything else that used to be SQL `NULL` is now the zero value in a column
that still accepts `NULL`, so a legacy row reads back the same. `unsetText`
is the predicate for "absent", covering both.

## What `Provision` adds beside `spec.Migrate`

Three things the declaration has no way to carry. `cmd/ddl` prints them after
the generated block, so a spec can be reviewed as SQL before it is trusted.

1. **The three Postgres `SEQUENCE`s** the id minting reads, so ids stay
   `device-<n>`, `chal-<n>` and `opcred-<n>`. SQLite has no sequence and
   falls back to a uuid suffix; nothing asserts on the digits.
2. **The one-live-salt index**, which is unique over an *expression*
   (`retired_at IS NULL`) rather than over a column. `spec.Index` takes
   fields or a document path, so this cannot be declared. Only
   `postgres_integration_test.go` exercises it.
3. **The one-off rewrite** of the sign-out reason `"member"` to `"self"`.

Following `mwanachama-backend-git`, which applies its own full-text index the
same way, rather than growing the format for one consumer.

## Legacy adoption covers two deployments

The pre-spec tables were named differently in each deployment: the retired
api-gateway used `operator_credential` while `mwanachama-wakala-api` uses
`auth_operator_credential`. `Provision` runs `spec.AdoptLegacy` once per name
set, through `spec.Legacy.Tables` — the shared helper that landed for this
(S48 there), rather than a per-repo adoption path.

Adoption renames the table, drops the legacy indexes, and renames
`member_id` to `subject_id` and `failed_attempts` to `failed`. It refuses
by name if both the legacy and the declared table exist and the legacy one
still holds rows, which is the case where converting would orphan data.

**Running it against a live database is an operator step**, not something a
startup should be assumed to have done safely. The two live table sets hold
credentials that automated routines sign in with.

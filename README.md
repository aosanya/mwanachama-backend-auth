# mwanachama-backend-auth

Identity and credentials: device registration and challenge/verify sign-in, operator email and password credentials, and phone-number verification.

A Go library backed by Postgres through GORM. It is imported directly by the
Mwanachama API gateway; there is no separate service to run.

## Use

```sh
go get github.com/aosanya/mwanachama-backend-auth
```

`Migrate(db, tables)` creates the tables, and the stores (`NewAuthStore`, `NewOperatorStore`,
`NewVerificationStore`, `NewPhoneSaltStore`) are what the rest of your code calls. The `routes/` package builds the HTTP
handlers for the surface that needs no gateway-specific wiring.

## Test

```sh
go test ./...
```

Unit tests run against in-memory SQLite. `postgres_integration_test.go` runs
against a real Postgres only when `POSTGRES_URL` is set.

## Licence

Apache-2.0. See [LICENSE](LICENSE). Design notes and the task board are in
[documentation/](documentation/).

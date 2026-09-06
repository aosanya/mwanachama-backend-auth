# mwanachama-backend-auth — open board

Nothing pending in this repo as of this pass. DEV-1649 through DEV-1654 (the
five-domain port + `routes/`) are complete — see `todo_done.md` for the
full record.

DEV-1655 (wire this repo into the gateway's `go.mod`/`cmd/server/stores.go`),
DEV-1656 (cut the gateway's HTTP layer over to `routes/`, delete the
superseded `internal/domain` packages) and DEV-1657 (archive the superseded
Postgres migrations, green `make test` on both repos) all live on the
gateway's own board
(`mwanachama-backend-api-gateway/documentation/3. implementation/todo_auth_standup.md`)
— they are follow-up work on that repo, not this one, and are explicitly out
of scope for this pass.

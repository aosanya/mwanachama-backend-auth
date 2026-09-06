# mwanachama-backend-auth — documentation

## Layout

Four folders, in SDLC order, and everything lives under one of them.

| Folder | What's inside |
|--------|---------------|
| [1. requirements/](1.%20requirements/) | Why this repo exists, what it ports, and the scope decisions made while porting it. |
| [2. design/](2.%20design/) | The models/gormstore/routes shape and the naming-collision resolution. |
| [3. implementation/](3.%20implementation/) | The work: `todo.md` (open board, pending only), `todo_done.md` (completed rows + prose context). |
| [4. qa/](4.%20qa/) | Test coverage notes — empty for now; see `todo_done.md` for what is covered. |

## What this repo is

The identity/credential cluster extracted from
[mwanachama-backend-api-gateway](../mwanachama-backend-api-gateway)'s
`internal/domain/{auth,operator,verification,phonenumber,phonesalt}` —
DEV-1649 through DEV-1654 on that repo's own
`documentation/3. implementation/todo_auth_standup.md`. Modelled on
[mwanachama-backend-actor](../mwanachama-backend-actor) and
[mwanachama-backend-comm](../mwanachama-backend-comm)'s identical shape: no
HTTP/gRPC service of its own, `models/`+`gormstore/` domain/storage split,
GORM not entitygraph, a `routes/` HTTP surface for the portable half of the
gateway's original handlers. See [CLAUDE.md](../CLAUDE.md) for the full
picture.

Currently: all five domains ported into `models/`+`gormstore/`+root-package
`*Store` implementations, `routes/` built for every handler the gateway's
own documentation classifies as portable, `go build`/`go vet`/`go test`
clean against sqlite. Not yet wired into the gateway — that is DEV-1655/1656,
explicitly out of scope for this repo's own build.

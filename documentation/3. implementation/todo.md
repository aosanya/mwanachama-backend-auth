# mwanachama-backend-auth — open board

Nothing pending, in this repo or on the gateway's side of this standup.
DEV-1649 through DEV-1654 (the five-domain port + `routes/`, this repo) and
DEV-1655 through DEV-1657 (the gateway wiring, HTTP cutover and migration
archival) are all complete — see `todo_done.md` for this repo's own record,
and the gateway's
`mwanachama-backend-api-gateway/documentation/3. implementation/todo_done.md`
(rows filed under `todo_auth_standup.md`) for the cutover half.

The gateway's `internal/domain/{auth,operator,verification,phonenumber,
phonesalt}` and their `internal/store/{memory,postgres}` implementations are
deleted; every HTTP route this repo's `routes/` package answers is mounted
from `mwanachama-backend-api-gateway/internal/api/http/router.go`, and every
route that stayed gateway-side (`registerDevice`, `signOutDevice`,
`phoneChallenge`/`phoneVerify`, `createOperatorCredential`,
`getVerification`, `submitVerification`) now calls into this repo's own
`models`/root-package types instead.

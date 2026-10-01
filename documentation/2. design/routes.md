# The route table

Every address this package answers is declared in
[`auth.operations.json`](../../auth.operations.json) — the method, the path,
the action id, the success status, a title and a description — and
`routes/routes.go` binds a handler to each one. There is no list of Go route
builders any more.

## Why every address is `handled`

The engine's `dispatch` can build a handler for an operation that names one
`call` on one manager: decode the request, call the method, encode the
result. Six of this module's ten addresses are not that shape, and the four
that are reach four different stores.

An orchestration is an address whose behaviour is **the order it does things
in**, not the call it ends with:

| Address | What the order is protecting |
| --- | --- |
| `auth.device.challenge` | Reads the device, refuses a signed-out one in exactly the words an unknown one gets, mints a nonce, and answers a projection with the subject blanked. A caller who could tell the two refusals apart would learn which device ids were once real. |
| `auth.device.verify` | Re-checks the sign-out *after* the challenge was minted, so a challenge minted a moment before a sign-out is not still spendable. Every way the proof can be wrong is one refusal. |
| `auth.recovery.verify` | Mints the session and ends every *other* device the subject held, which is not the plural of signing one device out: a device may only sign itself out, because on the branch that matters the attacker holds the other handset. |
| `auth.operator.signin` | Counts a failed attempt for an address that holds no credential exactly as for one that does, so the status, the remaining-tries count and the refusal sentence are byte-for-byte identical. The clock is a separate matter and is filed. |
| `auth.operator.password_change` | Checks the caller owns the credential before replacing the verifier, and does **not** clear the lock-out, because a password change is not proof the guesser has gone. |
| `auth.recovery.request` | Withholds the secret unless the mount asked for it, a dev-only flag whose zero value is the safe one. |

Rewriting those as declared calls is exactly where a refactor loses a
security property, and one of these orderings is already a filed bug
(DEV-1701: the challenge is consumed before the proof is checked, so one
wrong guess burns it for the legitimate holder). So the declaration carries
the address and the module carries the handler: `"handled": true` in the
operations file, bound by action id in `routes/routes.go`.

The remaining four — the credential list and disable, the verification set,
the phone-salt list — *are* single calls, but they live on
`OperatorRepository`, `VerificationRepository` and `PhoneSaltRepository`
rather than on one manager. Dispatching them needs a combined facade; that is
a follow-up on the board rather than something half-built here.

## What the declaration still owns

`"handled"` is not an escape hatch. The declaration owns:

- **The address.** Method and path come from the file. A path that moves
  moves there.
- **The action id.** `<module>.<resource>.<verb>`, stable across a path
  change and across domains, which is what a grant can be written against.
  This is the vocabulary DEV-1700 needs in order to own a role→action table
  at all.
- **The status.** The success code each address answers with.
- **The error map.** Every exported sentinel is mapped to a status.
  `TestEverySentinelIsMappedToAStatus` holds the two sets to each other in
  both directions, because an unmapped sentinel is redacted to a 500 and a
  400-shaped refusal then arrives as an unexplained server fault.
- **The gate.** `AnonymousActions` is an allowlist of five action ids, so a
  mount names actions rather than this package's Go identifiers.

And the binding is checked rather than assumed: `Build` refuses, by name,
both an action that is declared with no handler bound to it and a handler
bound to an action nobody declared.

## The gate

Five addresses are public by necessity — a caller proving a device or an
address has no session yet, so there is nothing to check:

```text
auth.device.challenge
auth.device.verify
auth.recovery.request
auth.recovery.verify
auth.operator.signin
```

`AnonymousActions` names **what is open, never what is protected**. An
address added later and not named there arrives gated, so the failure
direction is a 401 rather than the whole surface on the public internet.
`Split` is how a mount separates the two halves.

This module still has no auth model of its own: a gated route needs a
capability check wrapped around it by whatever mounts it. The role→action
grant table is DEV-1700, and these action ids are its input.

## What stays out

`routes/doc.go` carries the full list of addresses that belong to a mounting
process rather than to this package, and why — a handler that composes a
domain this repo must not depend on stays where that domain lives. Session
minting is the clearest case: `SessionMinter` is a seam the mount supplies,
because a session is the mount's to issue.

## The wire

`httpwire` supplies `WriteJSON`, `WriteErr`, `ReadJSON`, `Route` and
`Route.Pattern`. This package carried its own copies of all five until
DEV-1702; `Route` is now a type alias, so the exported surface a mount sees
did not move. `routes/wire.go` keeps only `randHex`, which is this module's
own nonce source.

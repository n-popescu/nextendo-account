# Wiring the friends fix into `main.go`

Everything else in this branch is committed normally. This one patch carries the
`main.go` changes, for a practical reason: it was pushed through the GitHub API, which
writes whole files, and `main.go` is 3101 lines. Reproducing it by hand to change 40
lines risks silently altering account-server behaviour, so the change ships as a
git-generated diff instead — byte-exact, and it applies cleanly to `main`.

```sh
git apply contrib/0001-wire-friends-fix-into-main.patch
go build ./... && go test ./...
git commit -am "friends: wire the console bindings and presence into main"
```

## What it changes (four spots, ~40 lines)

**1. Registers the four new routes** next to the existing `/internal/*` ones, each behind
the same `internalOnly` guard:

```
/internal/whoami     console (sub + bs:did) -> account, 404 otherwise
/internal/bind       records the REAL identity a console presents
/internal/unbind     removes a binding (moving a console between accounts)
/internal/presence   a single-account presence write for a server-to-server caller
```

Without this hunk the handlers exist and are tested but nothing routes to them, so the
fix is unreachable in production.

**2. `internalPIDByBsDid` now resolves through the binding index** instead of walking
every account and comparing against the derived `BsDid`. That loop was the bug's origin:
a console with a pre-existing device account presents its own id, never ours, so the
lookup 404s and `nx-account` fell back to a default account. It now goes through
`resolveConsole` (bindings first, then derived ids) and logs an explicit line when it
cannot resolve — the case that must end in a refusal, never a default identity. Also
O(1) instead of O(accounts) on a path a console hits constantly.

**3. `internalIdentity` and `internalLogin` call `noteConsoleOnline`.** Those endpoints
are called *by* `nx-account` on the console's behalf, so reaching them is proof the
console is on and connected. This is the presence half that needs **no `nx-account`
change at all** — and without it a friend only ever looks online while inside a NEX game,
which is why friends appeared permanently offline.

## Verifying it landed

```sh
curl -i -H "X-Internal-Key: $NEXTENDO_INTERNAL_KEY" \
  "http://127.0.0.1:8080/internal/whoami?baas=deadbeefdeadbeef&bsdid=0000000000000000"
```

`404 {"found":false}` is the correct answer, and it is the whole point: an unresolvable
console must be refused, never attached to a default account. A `302` means the route is
not registered (the patch was not applied); a `401` means the internal key does not match.

# Fixing the Switch friends system

This fork adds the server-side half of the fix for two problems reported on real
Switch hardware:

> **A.** A lot of people are friends but never appear online — as if the online status is never shared.
>
> **B.** When adding someone on the Switch, it adds them **as the person who wrote the code**: his
> friend code always appears. Reissuing a friend code does not help.

Nothing in this fork changes how the website or the existing games behave. Every addition is a new
`/internal/*` route or a new field; existing routes keep their shape.

---

## Problem B: every console resolves to one account

### What was happening

A Switch presents a BAAS `id_token` on every request:

```
sub      the BAAS/NSA user id   (per console USER)
bs:did   the device account id  (per console)
```

`nx-account` (the Switch-facing server, not in the public org) must turn that into a Nextendo account
on **every** request. The only tool it had was `/internal/pid-by-bsdid`, which compares `bs:did`
against a value **derived from the account PID**:

```go
BsDid = HMAC(secret, "bsdid:" + pid)[:8]
```

That works only if the console adopts the id *we* minted. A console caches its device account in
system save `8000000000000010` and presents **its own** id forever — so a console provisioned before
the account existed, or provisioned while somebody else's account was linked, matches nothing. The
lookup 404s, and `nx-account` then falls back to a process-wide "last authenticated account"
variable. The comment on `internalPIDByBsDid` in `main.go` says so in as many words:

> *"Sans ça, nx-account retombait sur une variable globale (le dernier compte authentifié) et livrait
> le compte d'autrui."*

Result: every console converges on one identity — whoever set the server up. His friend code is shown
to everybody, and friend requests are sent as him. Reissuing a friend code changes the code, not the
binding, which is exactly what was observed.

### What this fork adds

**A real binding table.** The ids a console *actually presents*, stored per account, several per
account (one per console or profile):

```json
"nintendo_bindings": [
  { "baas_id": "8ca8d7842f865b2f", "bs_did": "581ea786a91f1689",
    "label": "switch-lite", "bound_at": "…", "last_seen": "…" }
]
```

**`GET /internal/whoami?baas=<sub>&bsdid=<bs:did>`** — the single resolution entry point:

```json
200 {"found":true,"pid":1800000042,"via":"binding:baas","nickname":"…","friendCode":"SW-…"}
404 {"found":false}
```

Resolution order: explicit binding on `baas` → explicit binding on `bs_did` → derived `BaasID` →
derived `BsDid`. **There is deliberately no fifth step**: an unresolvable console gets 404 and the
caller must refuse the request. It is never turned into a default, a "last seen" or a "first"
account.

**`POST /internal/bind`** — records a binding, called by the console link flow with the ids from the
token the console *actually presented*. This is what makes a console with a pre-existing device
account work **without a factory reset**: instead of expecting it to adopt our derived id, we learn
its own.

A binding belongs to exactly one account. Binding an id that another account already owns is refused
with **409**, not silently moved — a console quietly changing owner would be the same bug in a new
shape.

**`POST /internal/unbind`** — removes a binding, which is the recovery path for a console poisoned by
the old fallback (unbind from the wrong account, bind to the right one).

**`/internal/pid-by-bsdid` now uses the binding index too**, so `nx-account` improves even before it
is changed, and both endpoints log an explicit line when they cannot resolve.

**O(1) resolution.** The old lookup walked every account on every console request (also a small
denial-of-service surface). The bindings are indexed in memory and rebuilt on write.

**Hex and decimal are the same id.** A console id is a 64-bit number that appears as 16 hex characters
in an `id_token` and in decimal on other paths (`/api/nsa` is called with the decimal form). Ids are
canonicalised to `%016x`, with the ambiguity resolved by length (exactly 16 hex characters is hex,
otherwise decimal is tried first).

---

## Problem A: friends never appear online

### What was happening

`presence.go` is an in-memory table with a 90-second TTL and **two** writers:

| Writer | Covers |
| --- | --- |
| `POST /api/presence` | an emulator user, mostly around private-battle hosting |
| `POST /internal/presence-batch` | a player **inside** Splatoon 2 / MK8 / … |

Nothing reported a console that is simply **on and online** — Home Menu, a game with no Nextendo
server, or a menu before matchmaking. The Home Menu friend list is exactly where players look at each
other's status, so a friend was normally offline.

And `nx-account`, which *does* see the console's presence, had no way to write it: `/api/presence`
needs a user bearer token it does not have, and `presence-batch` is shaped for "these PIDs are in this
game".

### What this fork adds

**`POST /internal/presence`** — a single-account presence write for a server-to-server caller:

```json
{"pid":1800000042,"status":1,"app_id":"0100c2500fc20000","app_field":"<base64>"}
```

`status: 0` clears the presence **immediately**, so "went offline" is instant instead of a TTL expiry
— a friend list that takes 90 seconds to notice somebody left looks broken.

**Liveness from console traffic** (`noteConsoleOnline`). `/internal/identity`,
`/internal/pid-by-bsdid`, `/internal/whoami` and `/internal/login` are called *by* `nx-account` on the
console's behalf, so reaching them **is** proof the console is on and connected. Each now publishes an
"online" presence for the resolved account. This works with **no change on the `nx-account` side at
all**.

Two rules keep it honest:

- a **stronger, fresher presence is never downgraded** — a player in a game stays "playing", they do
  not get demoted to "online" by a friend-list poll;
- the console presence has its **own, longer TTL** (`NEXTENDO_CONSOLE_PRESENCE_TTL`, default 5 min),
  because a console polls less often than a game reports and 90 s would make friends flicker.

**Favorites and blocks in the NPLN bridge.** `/internal/npln-friends` now publishes `favorite` per
friend and a `blocked` array. Splatoon 3 reads both: without the flag every friend looks unstarred in
game while the website shows the star, and an empty block list lets the game match a player with
somebody they blocked.

---

## What `nx-account` still has to do

`nx-account` is not in the public organisation, so it could not be changed here. Its part is small:

1. **Resolve per request** with `GET /internal/whoami?baas=<sub>&bsdid=<bs:did>`, taking both values
   from the **`id_token` of the request being served**.
2. **Delete the global fallback.** On 404, answer the console with an authentication error. A player
   seeing "please link your Nextendo account" is a fixable problem; a player silently acting as
   somebody else is not.
3. **Cache per (`sub`, `bs:did`) pair only** — never in a process-wide variable.
4. **At link time, call `POST /internal/bind`** with the ids from the token the console presented, so
   its existing device account becomes the recognised binding.
5. **On the console's presence update, call `POST /internal/presence`** with the resolved caller's PID.
6. **When building the friend list**, map each friend's `presenceStatus` (already in
   `/internal/identity`'s `friends[]`) into the BAAS friend object, and mark presence
   deliverable/receivable in both directions.

Steps 1, 2 and 4 fix problem B. Steps 5 and 6 finish problem A (the liveness signal already helps
without them).

---

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `NEXTENDO_CONSOLE_PRESENCE_TTL` | `300` (seconds; a duration like `2m` also works) | how long a console counts as online after we last heard from it |
| `NEXTENDO_BINDINGS_FILE` | `nintendo_bindings.json` | where the console binding table is stored |

No other configuration changes. All new routes are `/internal/*` and are gated by
`internal_guard.go` plus `NEXTENDO_INTERNAL_KEY`, like their neighbours.

## Tests

```sh
go test -run "Whoami|Binding|ConsolePresence|InternalPresence|NplnFriends|Unbind|TwoProfiles" .
```

They encode the rules that matter, not just the happy path:

- an explicit binding resolves, and a **derived** id still resolves (old consoles keep working);
- an unknown console gets **404 with no `pid` field** — the regression guard for the whole bug;
- a binding is **exclusive** (409), and unbind → rebind moves a console deliberately;
- hex and decimal spellings of one id resolve to the same binding;
- two consoles on two accounts get **two different friend codes**;
- resolving an identity publishes presence, and does **not** downgrade a "playing" presence;
- `status: 0` clears presence at once; an unknown PID is refused;
- `npln-friends` publishes favorites and blocks.

## Testing it against real hardware

One console proves nothing: with a single console the buggy fallback returns the right account by
accident. The two-account, two-console procedure — plus the `curl` calls and the log lines to watch —
is in the Splatoon 3 repository's `docs/SETUP-HARDWARE.md`, part E.

## Recovering an already-poisoned console

The console has cached the owner's device account. After deploying this and the `nx-account` change:

- **bind it deliberately** — `POST /internal/unbind` on the owner's account for those ids, then sign in
  on the console with the intended account so the link flow binds them; or
- **reset the console's binding** — clear the local user's online binding (the Linkalho-style
  `isNnLinked` / device-account state described in `Prelude-Nro`'s notes) and let it provision fresh.

Reissuing a friend code does not help, and now there is a reason why: the code was never the identity.

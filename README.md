# csrftoken

[![Go Reference](https://pkg.go.dev/badge/github.com/chmike/csrftoken.svg)](https://pkg.go.dev/github.com/chmike/csrftoken)
[![Version](https://img.shields.io/github/v/tag/chmike/csrftoken?sort=semver&label=version)](https://github.com/chmike/csrftoken/tags)

Package `csrftoken` creates and verifies short CSRF tokens for Go web
applications. A token is bound to a session and identifies a transaction:
the form it was issued for.

- **Short**: 23 to 34 characters, base64url encoded.
- **Stateless verification**: no database access, the server recomputes the
  token MAC (HMAC-SHA256 truncated to 96 bits).
- **Bound to the session**: a token is only valid with the session id it was
  created for. The session id is not stored in the token.
- **Identifies a transaction**: the token carries a transaction id, used to
  retrieve the context of the form it was issued for.
- **Concurrent transactions**: any number of valid tokens may coexist, for
  instance one per open browser tab.
- **Limited lifetime**: each token has its own expiration time, up to 400
  days.
- **Fast and allocation free**: about 175 ns to create or verify a token,
  with no allocation.

The package also provides `TxStore`, an allocation free store of the
transactions of a session, with only two operations: `Add` and `Remove`.

## Installation

```bash
go get github.com/chmike/csrftoken
```

## Usage

The token key is derived from a 32 byte secret seed, the same as the one of
[securecookie](https://github.com/chmike/securecookie). The `Maker` only
keeps the derived key, not the seed.

```go
var tokens = csrftoken.MustNewMaker(seed)
```

Expiration times are of type `Expiration`, in unix seconds. `ExpireIn(ttl)`
returns the expiration time `ttl` from now.

When displaying a form, add a transaction to the session store. `Add`
returns the token to put in a hidden field of the form:

```go
func showForm(w http.ResponseWriter, r *http.Request) {
    sess := getSession(r) // application specific, sess.mu locked
    tok, txid, err := sess.Tx.Add(tokens, sess.ID,
        csrftoken.ExpireIn(15*time.Minute), &formContext{ /* ... */ })
    if err != nil {
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
    log.Printf("form displayed, txid %d", txid)
    w.Header().Set("Cache-Control", "no-store")
    tmpl.Execute(w, formData{CSRF: tok /* , ... */})
}
```

```html
<input type="hidden" name="csrf" value="{{.CSRF}}">
```

When the form is submitted, `Remove` verifies the token and removes the
transaction, so a second submission fails:

```go
func submitForm(w http.ResponseWriter, r *http.Request) {
    sess := getSession(r)
    ctx, exp, txid, err := sess.Tx.Remove(tokens, r.FormValue("csrf"), sess.ID)
    switch {
    case errors.Is(err, csrftoken.ErrTxUnknown):
        // The form was already submitted, or replaced by a newer version.
        log.Printf("stale form submitted, txid %d", txid)
        http.Redirect(w, r, "/form", http.StatusSeeOther)
        return
    case err != nil:
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    fc := ctx.(*formContext)
    if !valid(fc, r) {
        // Display the form again with a new token and the same expiration.
        tok, txid, err := sess.Tx.Add(tokens, sess.ID, exp, fc)
        // ... handle err, display the form with tok and the error messages
        return
    }
    // ... process the form, then redirect to the result page
    http.Redirect(w, r, "/done", http.StatusSeeOther)
}
```

A form displayed again, after an input error or for the next step of a form
with multiple steps, gets a new token with `Remove` then `Add`. Each
displayed version of a form thus has its own token, and only the last one is
valid. Submitting an older version, after going back in the browser
history, returns `ErrTxUnknown`. Reusing the expiration time bounds the
total duration of the transaction.

Two practices limit these cases:

- **Post/Redirect/Get**: after a successful submission, redirect to the
  result page with `303 See Other` instead of returning it. Reloading the
  page then reloads the result, and doesn't submit the form again.
- **`Cache-Control: no-store`** on the pages displaying a form: going back
  in the history then requests the page from the server, which displays an
  up to date form with a valid token.

The transaction id is only used to retrieve the transaction context. The
protection against CSRF relies on the MAC, the session id and the
expiration time.

`Create` and `Verify` create and verify a token without a `TxStore`.
`AppendCreate` appends the token to a byte slice and doesn't allocate when
the slice has enough capacity. `Create` allocates only the returned string.

## Example

The [example](example) directory contains a small web application using
csrftoken with securecookie: a login form protected by a token bound to a
pre-session cookie, and an order form using a `TxStore`, displayed again
after an input error, with the handling of double submissions and of the
browser back button. Its tests drive the application like a browser,
including CSRF attempts.

```bash
cd example
go run .
```

Then open <https://localhost:8443> and accept the warning about the self
signed certificate.

## Forms outside of an authenticated session

Forms like login, sign up, contact or password reset are displayed before
the user is authenticated. Without protection, a malicious page can make the
browser of a visitor submit them. The most harmful case is login CSRF: the
victim is silently logged in the attacker's account, and everything she
enters afterwards ends up in that account.

A token must be bound to something only the victim's browser has. A token
bound to nothing is useless: the attacker can get a valid one by displaying
the form himself. This is why an empty session id is rejected.

Use a pre-session cookie as session id:

1. When displaying the form, read the pre-session cookie. If it is absent,
   generate a random id of 16 bytes with `crypto/rand` and store it in the
   cookie. Reuse the cookie when it is present: a new id at each display
   would invalidate the forms open in other tabs.
   [securecookie](https://github.com/chmike/securecookie) does what is
   needed: it adds the `__Host-` prefix to the cookie name, sets the
   `Secure`, `HttpOnly` and `SameSite=Lax` attributes, and encrypts and
   authenticates the value with keys derived from the same seed.
2. Create the token with `Create` and the pre-session id, without a
   `TxStore`. The transaction id is not needed when the form has no
   context: use 0. The server stores nothing, so the pre-session costs no
   server memory, and an attacker can't exhaust it by displaying forms.
3. When the form is submitted, verify the token with `Verify` and the
   pre-session id read from the cookie. An attacker can't read nor set the
   victim's cookie, so his tokens are rejected.
4. After a successful login, delete the pre-session cookie and create a new
   authenticated session with a new session id.

An alternative, without token nor cookie, is the
[`http.CrossOriginProtection`](https://pkg.go.dev/net/http#CrossOriginProtection)
middleware of Go 1.25, which rejects cross-origin requests using the
`Sec-Fetch-Site` and `Origin` headers sent by all current browsers.

## Token format

Before base64url encoding, without padding:

| Field | Size     | Content                                                   |
|-------|----------|-----------------------------------------------------------|
| exp   | 4 bytes  | expiration time, unix seconds modulo 2³², big endian      |
| txid  | 1–9 bytes| transaction id, LEB128 variant limited to 9 bytes         |
| mac   | 12 bytes | HMAC-SHA256(key, exp ‖ txid ‖ session id), truncated      |

The expiration time is compared to the current time with a signed 32 bit
difference, so the wrap around of 2³² seconds is harmless.

The key is derived from the seed with HKDF-SHA256 (RFC 5869) using the info
`"csrftoken v1 key"`, distinct from the securecookie key derivation, so the
keys are independent.

## Transaction store

`TxStore` holds the live transactions of a session: their id, expiration
time and context. It is meant to be a field of the application session
object.

- `Add` adds a transaction and returns its token and transaction id.
  `Remove` verifies a token, removes its transaction and returns its
  context, expiration time and transaction id. The transaction id may be
  ignored, or logged to follow the interactions of a form.
- The zero value is ready to use. Transaction ids start at 1.
- The first eight transactions are stored in an array inside the
  `TxStore`, so a session with few transactions doesn't allocate.
- `Add` purges the expired transactions. When `MaxTx` (32) transactions are
  live, the oldest one is evicted: it is most likely an abandoned form.
- Store a pointer as context, or nil: a non pointer value is boxed in an
  interface, which allocates.
- A `TxStore` is not safe for concurrent use: protect it with the session
  mutex.

## Performance

Time per operation, for a transaction id of 1048576:

| Benchmark                                | Apple M2 | AMD Ryzen AI 9 HX PRO 370 | Allocations |
|------------------------------------------|---------:|--------------------------:|-------------|
| `Create`                                 |   175 ns |                    179 ns | 1 (string)  |
| `AppendCreate`                           |   164 ns |                    165 ns | 0           |
| `Verify`                                 |   177 ns |                    170 ns | 0           |
| `Verify`, token of another session       |   136 ns |                    131 ns | 0           |
| `TxStore` `Add` + `Remove`, a form cycle |   365 ns |                    364 ns | 1 (string)  |

Apple M2 on darwin/arm64. AMD on linux/amd64, median of 10 runs of
`go test -run='^$' -bench=. -benchmem -count=10` on a single core
(`taskset -c 0` and `-cpu=1`).

Rejecting a forged token is faster than verifying a valid one, since the
MAC is checked first.

## Security notes

- Tokens protect against CSRF, not against an attacker on the network path:
  serve the application over HTTPS only, with the `Strict-Transport-Security`
  header and `Secure` cookies.
- The seed must be kept secret. Changing it invalidates all tokens, and all
  securecookie values. There is no automatic key rotation.
- The MAC is checked before the expiration time, so `ErrExpired` is only
  returned for authentic tokens.
- For defense in depth, also use `SameSite` cookies and, with Go 1.25 or
  later, the [`http.CrossOriginProtection`](https://pkg.go.dev/net/http#CrossOriginProtection)
  middleware, which rejects cross-origin requests using the `Sec-Fetch-Site`
  and `Origin` headers.

## Related packages

- [securecookie](https://github.com/chmike/securecookie): secure cookies
  encrypted and authenticated with AES-GCM, with keys derived from the same
  seed as csrftoken. It can hold the session id and the pre-session id.

## Contributors

- Claude Opus 5.5 (Anthropic):
    - assisted with the design and implementation of the package, its
    tests, benchmarks and documentation.

## License

See the [LICENSE](LICENSE) file.

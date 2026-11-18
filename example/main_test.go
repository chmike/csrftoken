package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/chmike/securecookie/v2"
)

// The tests drive the application through HTTPS like a browser: each
// client has its own cookie jar, and doesn't follow redirections so that
// they can be checked.

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func newTestServer(t *testing.T) *httptest.Server {
	srv := httptest.NewTLSServer(newServer(securecookie.MustGenerateSeed()).handler())
	t.Cleanup(srv.Close)
	return srv
}

// client is a browser with its own cookies.
type client struct {
	t   *testing.T
	srv *httptest.Server
	hc  http.Client
}

func newClient(t *testing.T, srv *httptest.Server) *client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, srv: srv, hc: *srv.Client()}
	c.hc.Jar = jar
	c.hc.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

type response struct {
	status   int
	body     string
	location string
}

func (c *client) do(req *http.Request) response {
	c.t.Helper()
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	return response{status: resp.StatusCode, body: string(b), location: resp.Header.Get("Location")}
}

func (c *client) get(path string) response {
	c.t.Helper()
	req, err := http.NewRequest(http.MethodGet, c.srv.URL+path, nil)
	if err != nil {
		c.t.Fatal(err)
	}
	return c.do(req)
}

func (c *client) post(path string, form url.Values) response {
	c.t.Helper()
	req, err := http.NewRequest(http.MethodPost, c.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

// login logs the client in, or fails the test.
func (c *client) login() {
	c.t.Helper()
	r := c.get("/login")
	expect(c.t, r, http.StatusOK, "")
	r = c.post("/login", url.Values{"csrf": {token(c.t, r)}, "user": {"demo"}, "password": {"demo"}})
	expect(c.t, r, http.StatusSeeOther, "/order")
}

// token returns the CSRF token of the form in the page, or fails the test.
func token(t *testing.T, r response) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(r.body)
	if m == nil {
		t.Fatalf("no CSRF token in page:\n%s", r.body)
	}
	return m[1]
}

// expect fails the test if the response doesn't have the status and the
// redirection location.
func expect(t *testing.T, r response, status int, location string) {
	t.Helper()
	if r.status != status || r.location != location {
		t.Fatalf("got status %d, location %q, want %d, %q\n%s", r.status, r.location, status, location, r.body)
	}
}

// expectBody fails the test if the response body doesn't contain s.
func expectBody(t *testing.T, r response, s string) {
	t.Helper()
	if !strings.Contains(r.body, s) {
		t.Fatalf("page doesn't contain %q:\n%s", s, r.body)
	}
}

// orderValues returns the values of a submitted order form.
func orderValues(tok, product, quantity string) url.Values {
	return url.Values{"csrf": {tok}, "product": {product}, "quantity": {quantity}}
}

// tamper returns tok with its first character changed.
func tamper(tok string) string {
	if tok[0] == 'A' {
		return "B" + tok[1:]
	}
	return "A" + tok[1:]
}

func TestLogin(t *testing.T) {
	c := newClient(t, newTestServer(t))
	r := c.get("/")
	expect(t, r, http.StatusSeeOther, "/login")
	r = c.get("/login")
	expect(t, r, http.StatusOK, "")

	// Invalid password: the form is displayed again with the user name.
	r = c.post("/login", url.Values{"csrf": {token(t, r)}, "user": {"demo"}, "password": {"wrong"}})
	expect(t, r, http.StatusOK, "")
	expectBody(t, r, "Invalid user or password.")
	expectBody(t, r, `value="demo"`)

	r = c.post("/login", url.Values{"csrf": {token(t, r)}, "user": {"demo"}, "password": {"demo"}})
	expect(t, r, http.StatusSeeOther, "/order")
	r = c.get("/")
	expect(t, r, http.StatusSeeOther, "/order")
}

func TestLoginCSRF(t *testing.T) {
	// The attacker gets a valid login token by displaying the form himself,
	// and makes the browser of the victim submit it.
	srv := newTestServer(t)
	victim, attacker := newClient(t, srv), newClient(t, srv)
	tok := token(t, attacker.get("/login"))
	form := url.Values{"csrf": {tok}, "user": {"demo"}, "password": {"demo"}}

	// The victim has no pre-session cookie.
	expect(t, victim.post("/login", form), http.StatusForbidden, "")

	// The victim has its own pre-session cookie.
	victim.get("/login")
	expect(t, victim.post("/login", form), http.StatusForbidden, "")

	// The token is valid for the attacker.
	expect(t, attacker.post("/login", form), http.StatusSeeOther, "/order")
}

func TestLoginTwoTabs(t *testing.T) {
	// The pre-session cookie is reused, so a login form displayed in a first
	// tab remains valid after displaying it in a second tab.
	c := newClient(t, newTestServer(t))
	tok1 := token(t, c.get("/login"))
	c.get("/login")
	r := c.post("/login", url.Values{"csrf": {tok1}, "user": {"demo"}, "password": {"demo"}})
	expect(t, r, http.StatusSeeOther, "/order")
}

func TestNoSession(t *testing.T) {
	c := newClient(t, newTestServer(t))
	expect(t, c.get("/order"), http.StatusSeeOther, "/login")
	expect(t, c.post("/order", orderValues("x", "apple", "1")), http.StatusSeeOther, "/login")
	expect(t, c.get("/done"), http.StatusSeeOther, "/login")
	expect(t, c.post("/logout", url.Values{"csrf": {"x"}}), http.StatusSeeOther, "/login")
}

func TestOrder(t *testing.T) {
	c := newClient(t, newTestServer(t))
	c.login()
	r := c.get("/order")
	expect(t, r, http.StatusOK, "")
	tok1 := token(t, r)

	// Input error: the form is displayed again with the entered values and a
	// new token.
	r = c.post("/order", orderValues(tok1, "apple", "0"))
	expect(t, r, http.StatusOK, "")
	expectBody(t, r, "The quantity must be between 1 and 10.")
	expectBody(t, r, `value="apple"`)
	tok2 := token(t, r)
	if tok2 == tok1 {
		t.Fatal("the form displayed again has the same token")
	}

	// Going back in the history and submitting the previous version fails.
	r = c.post("/order", orderValues(tok1, "apple", "3"))
	expect(t, r, http.StatusConflict, "")
	expectBody(t, r, "already submitted")

	// The last version is valid.
	expect(t, c.post("/order", orderValues(tok2, "apple", "3")), http.StatusSeeOther, "/done")

	// Submitting it twice fails.
	expect(t, c.post("/order", orderValues(tok2, "apple", "3")), http.StatusConflict, "")

	r = c.get("/done")
	expect(t, r, http.StatusOK, "")
	expectBody(t, r, "3 × apple")
	if n := strings.Count(r.body, "<li>"); n != 1 {
		t.Errorf("got %d orders, want 1", n)
	}
}

func TestOrderInputErrors(t *testing.T) {
	c := newClient(t, newTestServer(t))
	c.login()
	tok := token(t, c.get("/order"))
	tests := []struct {
		product, quantity, msg string
	}{
		{"", "1", "The product is required."},
		{"apple", "", "The quantity must be between 1 and 10."},
		{"apple", "11", "The quantity must be between 1 and 10."},
		{"apple", "x", "The quantity must be between 1 and 10."},
	}
	for _, tt := range tests {
		r := c.post("/order", orderValues(tok, tt.product, tt.quantity))
		expect(t, r, http.StatusOK, "")
		expectBody(t, r, tt.msg)
		tok = token(t, r)
	}
	expect(t, c.post("/order", orderValues(tok, "apple", "10")), http.StatusSeeOther, "/done")
}

func TestOrderTwoTabs(t *testing.T) {
	// Forms displayed in two tabs are both valid.
	c := newClient(t, newTestServer(t))
	c.login()
	tok1 := token(t, c.get("/order"))
	tok2 := token(t, c.get("/order"))
	expect(t, c.post("/order", orderValues(tok2, "banana", "2")), http.StatusSeeOther, "/done")
	expect(t, c.post("/order", orderValues(tok1, "cherry", "1")), http.StatusSeeOther, "/done")
	r := c.get("/done")
	expectBody(t, r, "2 × banana")
	expectBody(t, r, "1 × cherry")
}

func TestOrderCSRF(t *testing.T) {
	srv := newTestServer(t)
	alice, bob := newClient(t, srv), newClient(t, srv)
	alice.login()
	bob.login()
	tok := token(t, alice.get("/order"))

	// A token of another session is rejected.
	expect(t, bob.post("/order", orderValues(tok, "apple", "1")), http.StatusForbidden, "")

	// Invalid tokens are rejected.
	for _, bad := range []string{"", "x", tok[:len(tok)-1], tamper(tok)} {
		expect(t, alice.post("/order", orderValues(bad, "apple", "1")), http.StatusForbidden, "")
	}

	// The rejected attempts didn't consume the transaction.
	expect(t, alice.post("/order", orderValues(tok, "apple", "1")), http.StatusSeeOther, "/done")
}

func TestLogout(t *testing.T) {
	c := newClient(t, newTestServer(t))
	c.login()
	tok := token(t, c.get("/done"))
	expect(t, c.post("/logout", url.Values{"csrf": {"x"}}), http.StatusForbidden, "")
	expect(t, c.post("/logout", url.Values{"csrf": {tok}}), http.StatusSeeOther, "/login")
	expect(t, c.get("/order"), http.StatusSeeOther, "/login")
}

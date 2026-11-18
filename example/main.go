// Command example is a small web application showing how to use the
// csrftoken package with securecookie.
//
// It has a login form displayed outside of a session, protected by a token
// bound to a pre-session cookie, and an order form displayed inside the
// session, whose transactions are kept in a TxStore. The order form shows
// how a form is displayed again after an input error, and what happens when
// a form is submitted twice or after going back in the browser history.
//
// Run it with
//
//	go run .
//
// and open https://localhost:8443 in a browser. The server uses a self
// signed certificate generated at startup, so the browser displays a
// warning that must be accepted. Log in with the user "demo" and the
// password "demo".
//
// HTTPS is required because securecookie cookies have the Secure attribute
// and the "__Host-" prefix.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"flag"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chmike/csrftoken"
	"github.com/chmike/securecookie/v2"
)

const (
	idLen         = 16               // byte length of session and pre-session ids
	loginTTL      = 10 * time.Minute // time to live of a login form
	orderTTL      = 15 * time.Minute // time to live of an order transaction
	sessionMaxAge = 8 * time.Hour    // maximum age of a session cookie
)

func main() {
	addr := flag.String("addr", "localhost:8443", "listen address")
	flag.Parse()

	// In a real application, the seed is read from a protected file, so that
	// cookies and tokens remain valid after a restart.
	seed := securecookie.MustGenerateSeed()

	cert, err := selfSignedCert("localhost")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:      *addr,
		Handler:   newServer(seed).handler(),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	log.Printf("listening on https://%s", *addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// server holds the state of the application.
type server struct {
	tokens     *csrftoken.Maker
	preCookie  *securecookie.Obj // pre-session id, before login
	sessCookie *securecookie.Obj // session id, after login

	mu       sync.Mutex
	sessions map[string]*session // by session id
}

// session is an authenticated session. A real application would also purge
// expired sessions.
type session struct {
	mu     sync.Mutex // protects all the fields below, tx included
	id     []byte
	user   string
	tx     csrftoken.TxStore
	orders []order
}

// order is a completed order.
type order struct {
	Product  string
	Quantity int
}

// orderForm is the context of an order transaction: the values entered by
// the user, displayed again after an input error.
type orderForm struct {
	Product  string
	Quantity string
}

// newServer returns a server whose cookie and token keys are derived from
// seed.
func newServer(seed []byte) *server {
	ks := securecookie.MustNewKeyStore(seed)
	return &server{
		tokens:     csrftoken.MustNewMaker(seed),
		preCookie:  securecookie.MustNew("pre", ks, time.Hour),
		sessCookie: securecookie.MustNew("session", ks, sessionMaxAge),
		sessions:   make(map[string]*session),
	}
}

// handler returns the HTTP handler of the application.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /login", s.showLogin)
	mux.HandleFunc("POST /login", s.submitLogin)
	mux.HandleFunc("GET /order", s.showOrder)
	mux.HandleFunc("POST /order", s.submitOrder)
	mux.HandleFunc("GET /done", s.showDone)
	mux.HandleFunc("POST /logout", s.submitLogout)
	return mux
}

// home redirects to the order form, or to the login form without session.
func (s *server) home(w http.ResponseWriter, r *http.Request) {
	if s.session(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/order", http.StatusSeeOther)
}

// ---- Login, outside of a session ----

// showLogin displays the login form.
func (s *server) showLogin(w http.ResponseWriter, r *http.Request) {
	s.renderLogin(w, r, "", "")
}

// renderLogin displays the login form with the user name and an error
// message. The token is bound to the pre-session id, and has no
// transaction: the server stores nothing for a pre-session.
func (s *server) renderLogin(w http.ResponseWriter, r *http.Request, user, msg string) {
	id, err := s.preSessionID(w, r)
	if err != nil {
		internalError(w, err)
		return
	}
	tok, err := s.tokens.Create(id, 0, csrftoken.ExpireIn(loginTTL))
	if err != nil {
		internalError(w, err)
		return
	}
	render(w, http.StatusOK, loginTmpl, loginData{CSRF: tok, User: user, Error: msg})
}

// submitLogin checks the login form. A real application would also throttle
// the login attempts per user name.
func (s *server) submitLogin(w http.ResponseWriter, r *http.Request) {
	id, _, err := s.preCookie.Value(nil, r)
	if err != nil {
		log.Printf("login: no valid pre-session cookie: %v", err)
		forbidden(w)
		return
	}
	user := r.PostFormValue("user")
	_, err = s.tokens.Verify(r.PostFormValue("csrf"), id)
	switch {
	case errors.Is(err, csrftoken.ErrExpired):
		s.renderLogin(w, r, user, "The form expired, please try again.")
		return
	case err != nil:
		log.Printf("login: token rejected: %v", err)
		forbidden(w)
		return
	}
	if !checkCredentials(user, r.PostFormValue("password")) {
		log.Printf("login: invalid credentials for %q", user)
		s.renderLogin(w, r, user, "Invalid user or password.")
		return
	}

	// Replace the pre-session by a new authenticated session.
	if err := s.preCookie.Delete(w); err != nil {
		internalError(w, err)
		return
	}
	if err := s.newSession(w, user); err != nil {
		internalError(w, err)
		return
	}
	log.Printf("login: %q logged in", user)
	http.Redirect(w, r, "/order", http.StatusSeeOther)
}

// preSessionID returns the pre-session id stored in the pre-session cookie.
// If the cookie is absent or invalid, a new id is generated and stored in
// the cookie. Reusing the existing id keeps valid the login forms open in
// other tabs.
func (s *server) preSessionID(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if id, _, err := s.preCookie.Value(nil, r); err == nil && len(id) == idLen {
		return id, nil
	}
	id := make([]byte, idLen)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	if err := s.preCookie.SetValue(w, id); err != nil {
		return nil, err
	}
	return id, nil
}

// checkCredentials returns true when user and password are valid. The
// comparison takes the same time whatever the values.
func checkCredentials(user, password string) bool {
	u := subtle.ConstantTimeCompare([]byte(user), []byte("demo"))
	p := subtle.ConstantTimeCompare([]byte(password), []byte("demo"))
	return u&p == 1
}

// ---- Session ----

// newSession creates an authenticated session for user and stores its id in
// the session cookie.
func (s *server) newSession(w http.ResponseWriter, user string) error {
	sess := &session{id: make([]byte, idLen), user: user}
	if _, err := rand.Read(sess.id); err != nil {
		return err
	}
	if err := s.sessCookie.SetValue(w, sess.id); err != nil {
		return err
	}
	s.mu.Lock()
	s.sessions[string(sess.id)] = sess
	s.mu.Unlock()
	return nil
}

// session returns the session of the request, or nil if there is none.
func (s *server) session(r *http.Request) *session {
	id, _, err := s.sessCookie.Value(nil, r)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[string(id)]
}

// ---- Order form, inside the session ----

// showOrder displays an empty order form.
func (s *server) showOrder(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	s.renderOrder(w, sess, &orderForm{Quantity: "1"}, csrftoken.ExpireIn(orderTTL), nil)
}

// renderOrder adds a transaction with form as context and exp as expiration
// time, and displays the order form with its token and the error messages.
// It must be called with the session mutex locked.
func (s *server) renderOrder(w http.ResponseWriter, sess *session, form *orderForm, exp csrftoken.Expiration, errs []string) {
	tok, txid, err := sess.tx.Add(s.tokens, sess.id, exp, form)
	if errors.Is(err, csrftoken.ErrExp) {
		// The transaction expires in less than a second.
		renderMessage(w, http.StatusOK, "The order form expired.", "/order", "New order")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	log.Printf("order: form displayed, txid %d", txid)
	render(w, http.StatusOK, orderTmpl, orderData{CSRF: tok, User: sess.user, Form: form, Errors: errs})
}

// submitOrder checks the order form. With an input error, the form is
// displayed again with a new token and the same expiration time, so only
// the last displayed version of the form is valid.
func (s *server) submitOrder(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()

	ctx, exp, txid, err := sess.tx.Remove(s.tokens, r.PostFormValue("csrf"), sess.id)
	switch {
	case errors.Is(err, csrftoken.ErrTxUnknown):
		log.Printf("order: stale form submitted, txid %d", txid)
		renderMessage(w, http.StatusConflict,
			"This form was already submitted, or replaced by a newer version.", "/done", "See your orders")
		return
	case errors.Is(err, csrftoken.ErrExpired):
		renderMessage(w, http.StatusOK, "The order form expired.", "/order", "New order")
		return
	case err != nil:
		log.Printf("order: token rejected: %v", err)
		forbidden(w)
		return
	}

	form := ctx.(*orderForm)
	form.Product = strings.TrimSpace(r.PostFormValue("product"))
	form.Quantity = strings.TrimSpace(r.PostFormValue("quantity"))
	var errs []string
	if form.Product == "" {
		errs = append(errs, "The product is required.")
	}
	qty, err := strconv.Atoi(form.Quantity)
	if err != nil || qty < 1 || qty > 10 {
		errs = append(errs, "The quantity must be between 1 and 10.")
	}
	if len(errs) > 0 {
		log.Printf("order: input error, txid %d", txid)
		s.renderOrder(w, sess, form, exp, errs)
		return
	}

	sess.orders = append(sess.orders, order{Product: form.Product, Quantity: qty})
	log.Printf("order: completed, txid %d", txid)
	// Post/Redirect/Get: reloading the result page doesn't submit the form again.
	http.Redirect(w, r, "/done", http.StatusSeeOther)
}

// showDone displays the orders of the session and a logout form.
func (s *server) showDone(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	// The logout form has no context: a token without transaction suffices.
	tok, err := s.tokens.Create(sess.id, 0, csrftoken.ExpireIn(sessionMaxAge))
	if err != nil {
		internalError(w, err)
		return
	}
	render(w, http.StatusOK, doneTmpl, doneData{CSRF: tok, User: sess.user, Orders: sess.orders})
}

// submitLogout ends the session.
func (s *server) submitLogout(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if _, err := s.tokens.Verify(r.PostFormValue("csrf"), sess.id); err != nil {
		log.Printf("logout: token rejected: %v", err)
		forbidden(w)
		return
	}
	s.mu.Lock()
	delete(s.sessions, string(sess.id))
	s.mu.Unlock()
	if err := s.sessCookie.Delete(w); err != nil {
		internalError(w, err)
		return
	}
	log.Printf("logout: %q logged out", sess.user)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- Rendering ----

// render executes the template t with data and writes the result with the
// status code. Pages are not stored by the browser, so going back in the
// history requests an up to date form from the server.
func render(w http.ResponseWriter, status int, t *template.Template, data any) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		internalError(w, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// renderMessage displays msg with a link.
func renderMessage(w http.ResponseWriter, status int, msg, link, label string) {
	render(w, status, messageTmpl, messageData{Msg: msg, Link: link, Label: label})
}

// forbidden displays a refused request page with a link to the home page,
// which leads to the order form or to the login form. The session is kept:
// an attacker can make a request fail at will, so logging the user out
// would give him a way to log out any user.
func forbidden(w http.ResponseWriter) {
	renderMessage(w, http.StatusForbidden, "This request was refused.", "/", "Home")
}

func internalError(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

type loginData struct {
	CSRF, User, Error string
}

type orderData struct {
	CSRF, User string
	Form       *orderForm
	Errors     []string
}

type doneData struct {
	CSRF, User string
	Orders     []order
}

type messageData struct {
	Msg, Link, Label string
}

const head = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>csrftoken example</title>
<link rel="icon" href="data:,">
<style>body{font-family:sans-serif;max-width:32em;margin:2em auto} .error{color:#b00}</style>
</head><body>`

var loginTmpl = template.Must(template.New("login").Parse(head + `
<h1>Login</h1>
{{with .Error}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/login">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<p><label>User <input name="user" value="{{.User}}" autofocus></label></p>
<p><label>Password <input name="password" type="password"></label></p>
<p><button>Log in</button></p>
</form>
<p>Use the user "demo" with the password "demo".</p>
</body></html>`))

var orderTmpl = template.Must(template.New("order").Parse(head + `
<h1>New order</h1>
<p>Logged in as {{.User}}. <a href="/done">Your orders</a></p>
{{range .Errors}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/order">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<p><label>Product <input name="product" value="{{.Form.Product}}" autofocus></label></p>
<p><label>Quantity (1 to 10) <input name="quantity" value="{{.Form.Quantity}}"></label></p>
<p><button>Order</button></p>
</form>
</body></html>`))

var doneTmpl = template.Must(template.New("done").Parse(head + `
<h1>Your orders</h1>
<p>Logged in as {{.User}}.</p>
{{if .Orders}}<ul>{{range .Orders}}<li>{{.Quantity}} × {{.Product}}</li>{{end}}</ul>
{{else}}<p>No order yet.</p>{{end}}
<p><a href="/order">New order</a></p>
<form method="post" action="/logout">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<p><button>Log out</button></p>
</form>
</body></html>`))

var messageTmpl = template.Must(template.New("message").Parse(head + `
<p>{{.Msg}}</p>
<p><a href="{{.Link}}">{{.Label}}</a></p>
</body></html>`))

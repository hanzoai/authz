// Package edge is the identity boundary: it strips what a client claimed, verifies
// the credential, and mints the headers everything behind it reads.
//
// It is SEPARATE from the decision (package authz) on purpose. A decision is a pure
// function of claims — Can(subject, verb, path) — and every plugin in the fleet asks
// it. An edge touches a request, so it links a transport. Folding the two together
// made the decision drag the whole HTTP stack into every caller that only wanted to
// ask a question, which is the same error as a dependency struct naming every client
// its callers might want.
//
// So: `authz` is the question, imported everywhere. `authz/edge` is the answer's
// custody, imported ONLY by whoever holds the edge role (HIP-0519).
//
// ONE EDGE, NOT ONE PER TRANSPORT. The estate serves on zip and also fronts an
// HTTP proxy edge, and when each held its own copy of this reasoning they drifted:
// the platform-authority header was corrected in one and went on being minted from
// an org role in the other. So the rules here take a [Headers] — the three
// operations rewriting an identity needs — which net/http's own header type
// satisfies as written and a zip request reaches through [Of].
package edge

import (
	"encoding/base64"
	"strings"

	"github.com/hanzoai/authz"
)

// Headers is the header set an edge rewrites. It is the smallest surface the rules
// below use, so a transport qualifies by having it rather than by being named here:
// net/http's http.Header satisfies it with no adapter at all.
type Headers interface {
	Get(name string) string
	Set(name, value string)
	Del(name string)
}

// Peeker is the OTHER shape a header set comes in: fasthttp's, where reading
// returns bytes. A zip request's headers are one — reach them with
//
//	edge.Of(&c.Fiber().Request().Header)
//
// It is stated as an interface rather than imported as a type on purpose. Naming
// the type would make this package depend on the whole zip/fasthttp stack, and then
// every consumer would link it for one adapter — which is the same mistake as a
// decision that drags an HTTP client into a caller that only wanted to ask a
// question. Neither transport is named here; both qualify by shape.
type Peeker interface {
	Peek(name string) []byte
	Set(name, value string)
	Del(name string)
}

// Of adapts a byte-returning header set to [Headers].
func Of(h Peeker) Headers {
	if h == nil {
		return nil
	}
	return peeker{h}
}

type peeker struct{ h Peeker }

func (p peeker) Get(name string) string { return string(p.h.Peek(name)) }
func (p peeker) Set(name, value string) { p.h.Set(name, value) }
func (p peeker) Del(name string)        { p.h.Del(name) }

// Strip deletes every identity header a client supplied and returns the org it had
// CLAIMED, which is an input to scope selection and never an authority.
//
// The claimed org is RETURNED rather than left on the request precisely so it
// cannot be mistaken for a minted one: the only way to act on it is to hand it to
// Inject, which admits it only if the signed membership set does.
//
// The capture and the strip are ONE operation because the selection must be read
// BEFORE the header is deleted. A separate "read it first" function would be an
// ordering trap that fails silently — the org switcher would simply stop working —
// and a caller that ignores the return value keeps the safe behaviour: nothing
// claimed, nothing minted.
func Strip(h Headers) (claimedOrg string) {
	if h == nil {
		return ""
	}
	claimedOrg = h.Get(authz.HeaderOrg)
	if authz.HasUnsafeRune(claimedOrg) {
		claimedOrg = "" // not an injective identifier: it grants nothing
	}
	for _, name := range authz.Headers {
		h.Del(name)
	}
	for _, name := range authz.Retired {
		h.Del(name)
	}
	return claimedOrg
}

// Inject applies [Mint] — the identity a verified token entitles this request to
// carry — to the headers the next tier reads.
func Inject(h Headers, cl *authz.Claims, selected string, at *authz.Grant) {
	if h == nil {
		return
	}
	for _, m := range Mint(cl, selected, at) {
		h.Set(m.Name, m.Value)
	}
}

// Header is one minted name and its value.
type Header struct{ Name, Value string }

// Mint is the identity decision AS A VALUE: the headers a verified token entitles
// this request to carry, with the zero values already dropped.
//
// selected is the org the client asked to act in, as returned by [Strip]; it is
// honoured only when the signed membership set admits it, or when the caller may
// masquerade. at is the grant the edge RESOLVED for this request, or nil when none
// was requested — and it is minted only when it belongs to THIS subject, because an
// edge forwarding a grant resolved for anyone else is the whole class of bug this
// package exists to prevent, one tier deeper.
//
// TWO ADMIN SCOPES, TWO HEADERS, never interchangeable. HeaderUserAdmin is PLATFORM
// authority — a human whose home org is the reserved admin org. HeaderUserOrgAdmin
// is admin of one's OWN org, resolved against the EFFECTIVE org so an operator
// viewing another tenant carries sudo without that tenant's self-service authority.
//
// Minting the platform header from Claims.IsAdmin — the ORG-role bit — is the
// escalation this package makes unrepeatable: every org owner arrived as a platform
// admin, and the money gates read that header.
//
// Absent is distinct from empty throughout: a header whose value is the zero value
// is not in the slice, so applying it never writes a header the token did not earn
// and never blanks one.
func Mint(cl *authz.Claims, selected string, at *authz.Grant) []Header {
	if cl == nil {
		return nil
	}
	effective, _ := cl.EffectiveOrg(selected)

	out := make([]Header, 0, 10)
	set := func(name, v string) {
		if v != "" {
			out = append(out, Header{name, v})
		}
	}
	set(authz.HeaderOrg, effective)
	set(authz.HeaderUserOwner, cl.Owner) // the immutable HOME org, distinct from the effective one

	// The sub-scopes are minted per CLAIM, each its own scalar and each refused if it
	// is not an injective identifier.
	//
	// Deliberately NOT assembled from [Claims.Location]: a project may sit directly
	// under an org (IAM emits `project` today and no `workspace` at all), and a
	// Location — which needs each segment's parent to be a path at all — would
	// suppress the project header entirely and silently drop a scope that works now.
	// The two answer different questions: these headers say WHICH project, Location
	// says what path the token names. A consumer that wants the path reads
	// HeaderScope, which carries the RESOLVED one; assembling a path out of these
	// scalars is what would let a workspace and a project of the same name collide.
	for name, seg := range map[string]string{
		authz.HeaderWorkspace: cl.Workspace,
		authz.HeaderProject:   cl.Project,
	} {
		if !authz.HasUnsafeRune(seg) {
			set(name, seg)
		}
	}
	set(authz.HeaderUser, cl.UserID())
	set(authz.HeaderUserName, cl.Username())
	set(authz.HeaderUserEmail, cl.Email)
	set(authz.HeaderBillingAccount, cl.BillingAccount)

	// The resolved LOCATION travels, not the grant set: the edge resolves once and
	// mints the outcome, so the token stays constant-size and no decision behind
	// the edge performs I/O. A grant belonging to another subject is not minted.
	if at != nil && at.Subject == cl.UserID() && len(at.Scope) > 0 {
		set(authz.HeaderScope, at.Scope.String())
		set(authz.HeaderScopeRole, string(at.Role))
	}

	if cl.PlatformSudo() {
		set(authz.HeaderUserAdmin, "true")
	}
	if cl.OrgAdmin(effective) {
		set(authz.HeaderUserOrgAdmin, "true")
	}
	return out
}

// Token extracts the credential a request carries, from — in order — an
// Authorization or X-Authorization Bearer, HTTP Basic (the password, which is how a
// .netrc credential reaches a proxy), then a session cookie.
func Token(h Headers) string {
	if t := Bearer(h); t != "" {
		return t
	}
	if t := Basic(h); t != "" {
		return t
	}
	return Cookie(h)
}

// Bearer extracts a Bearer token from Authorization or X-Authorization.
func Bearer(h Headers) string {
	if h == nil {
		return ""
	}
	auth := h.Get("Authorization")
	if auth == "" {
		auth = h.Get("X-Authorization")
	}
	scheme, rest, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(rest)
}

// Basic extracts the token from an HTTP Basic Authorization header: the password,
// falling back to the username when the password is empty. This is how a `go`
// client authenticates to a module proxy from ~/.netrc —
//
//	machine goproxy.hanzo.ai login <email> password <IAM token>
//
// — so the username is an address, not a secret, and the token may arrive in either
// field.
func Basic(h Headers) string {
	if h == nil {
		return ""
	}
	scheme, rest, ok := strings.Cut(h.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil {
		return ""
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return ""
	}
	if pass != "" {
		return pass
	}
	return user
}

// cookieNames are the session cookies a first-party sign-in mints, most trustworthy
// first.
//
// __Host-hanzo_iam_token leads and is the name to mint: the __Host- prefix is
// browser-enforced, so such a cookie may only be set Secure, Path=/, and WITHOUT a
// Domain attribute — a sibling host cannot set a Domain-scoped cookie of the same
// name to shadow it. The unprefixed names stay for clients that already mint them,
// and are read only when no un-shadowable cookie is present.
var cookieNames = []string{
	"__Host-hanzo_iam_token", "hanzo_iam_token",
	"iam_access_token", "access_token", "hanzo_token",
}

// Cookie extracts an access token from the session cookie names a first-party
// sign-in mints.
//
// The Cookie header is parsed here rather than delegated to a transport's own
// accessor, so both edges read the same names in the same order. A duplicate name
// takes the FIRST value: a later one is what an attacker who can set a cookie on a
// sibling host appends, and last-wins would let it overwrite the real session.
func Cookie(h Headers) string {
	if h == nil {
		return ""
	}
	jar := h.Get("Cookie")
	if jar == "" {
		return ""
	}
	for _, want := range cookieNames {
		rest := jar
		for rest != "" {
			var pair string
			pair, rest, _ = strings.Cut(rest, ";")
			name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if ok && name == want {
				if v := strings.Trim(strings.TrimSpace(value), `"`); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

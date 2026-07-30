// Package edge is the identity boundary: it strips what a client claimed,
// verifies the credential, and mints the headers everything behind it reads.
//
// It is SEPARATE from the decision (package authz) on purpose. A decision is a
// pure function of claims — Can(subject, verb, path) — and every plugin in the
// fleet asks it. An edge touches a request, so it links a transport. Folding the
// two together made the decision drag the whole HTTP stack into every caller
// that only wanted to ask a question, which is the same error as a dependency
// struct naming every client its callers might want.
//
// So: `authz` is the question, imported everywhere. `authz/edge` is the answer's
// custody, imported ONLY by whoever holds the edge role (HIP-0519). Today that
// is the gateway, and the gateway already serves on zip.
//
// ZIP-NATIVE. The request is a *zip.Ctx, which is what the fleet serves on, so
// there is no second HTTP type in the graph and nothing to convert at the seam.
package edge

import (
	"encoding/base64"
	"strings"

	"github.com/hanzoai/authz"
	"github.com/zap-proto/zip"
)

// Strip deletes every identity header a client supplied and returns the org it
// had CLAIMED, which is an input to scope selection and never an authority.
//
// The claimed org is RETURNED rather than left on the request precisely so it
// cannot be mistaken for a minted one: the only way to act on it is to hand it to
// Inject, which admits it only if the signed membership set does.
func Strip(c *zip.Ctx) (claimedOrg string) {
	if c == nil {
		return ""
	}
	h := &c.Fiber().Request().Header
	claimedOrg = string(h.Peek(authz.HeaderOrg))
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

// Inject mints the identity headers from VERIFIED claims. selected is the org the
// client asked to act in, as returned by Strip; it is honoured only when the
// signed membership set admits it, or when the caller may masquerade.
//
// at is the grant the edge RESOLVED for this request, or nil when none was
// requested. It is minted only when it belongs to THIS subject: an edge
// forwarding a grant resolved for anyone else is the whole class of bug this
// package exists to prevent, one tier deeper.
//
// TWO ADMIN SCOPES, TWO HEADERS, never interchangeable. HeaderUserAdmin is
// PLATFORM authority — a human whose home org is the reserved admin org.
// HeaderUserOrgAdmin is admin of one's OWN org, resolved against the EFFECTIVE
// org so an operator viewing another tenant carries sudo without that tenant's
// self-service authority.
//
// Minting the platform header from Claims.IsAdmin — the ORG-role bit — is the
// escalation this package makes unrepeatable: every org owner arrived as a
// platform admin, and the money gates read that header.
func Inject(c *zip.Ctx, cl *authz.Claims, selected string, at *authz.Grant) {
	if c == nil || cl == nil {
		return
	}
	h := &c.Fiber().Request().Header
	effective, _ := cl.EffectiveOrg(selected)

	set := func(name, v string) {
		if v != "" {
			h.Set(name, v)
		}
	}
	set(authz.HeaderOrg, effective)
	set(authz.HeaderUserOwner, cl.Owner) // the immutable HOME org, distinct from the effective one
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
		h.Set(authz.HeaderUserAdmin, "true")
	}
	if cl.OrgAdmin(effective) {
		h.Set(authz.HeaderUserOrgAdmin, "true")
	}
}

// Token extracts the credential a request carries, from — in order — an
// Authorization or X-Authorization Bearer, HTTP Basic (the password, which is how
// a .netrc credential reaches a proxy), then a session cookie.
func Token(c *zip.Ctx) string {
	if t := Bearer(c); t != "" {
		return t
	}
	if t := Basic(c); t != "" {
		return t
	}
	return Cookie(c)
}

// Bearer extracts a Bearer token from Authorization or X-Authorization.
func Bearer(c *zip.Ctx) string {
	if c == nil {
		return ""
	}
	auth := c.Header("Authorization")
	if auth == "" {
		auth = c.Header("X-Authorization")
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
// — so the username is an address, not a secret, and the token may arrive in
// either field.
func Basic(c *zip.Ctx) string {
	if c == nil {
		return ""
	}
	scheme, rest, ok := strings.Cut(c.Header("Authorization"), " ")
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

// Cookie extracts an access token from the session cookie names a first-party
// sign-in mints.
//
// __Host-hanzo_iam_token is first and is the name to mint: the __Host- prefix is
// browser-enforced, so such a cookie may only be set Secure, Path=/, and WITHOUT
// a Domain attribute — a sibling host cannot set a Domain-scoped cookie of the
// same name to shadow it. The unprefixed names stay for clients that already mint
// them, and are read only when no un-shadowable cookie is present.
func Cookie(c *zip.Ctx) string {
	if c == nil {
		return ""
	}
	for _, name := range []string{
		"__Host-hanzo_iam_token", "hanzo_iam_token",
		"iam_access_token", "access_token", "hanzo_token",
	} {
		if v := c.Fiber().Cookies(name); v != "" {
			return v
		}
	}
	return ""
}

// Package authz is the decision: who may do what, where. It is a stateless leaf —
// no store, no init, no config, no network on any path — so importing it costs a
// caller nothing and every subsystem can ask the same question the same way
// (HIP-0519).
//
// LOCATION and ACCESS are different questions, and conflating them is the bug
// this package exists to prevent.
//
// LOCATION is a PATH: org/workspace/project, and below it apps, sites, everything
// else — acme/prod/web, acme/prod/web/site/landing. It is total and unambiguous.
// It is what a resource IS: a human-meaningful name scoped by its parent, and the
// axis billing and quota roll up along.
//
// ACCESS is a GRANT AT A PREFIX: (subject, scope, role), where scope is a prefix
// of the path. Can reports true iff some grant's scope prefixes the target and
// its role admits the verb. ONE predicate covers orgs, workspaces, projects, apps
// and sites, with no special case — every arrangement falls out of prefix
// matching:
//
//	org-wide member        a grant at acme
//	workspace member       a grant at acme/prod
//	invite-only project    a grant at acme/prod/web with NO ancestor grant
//	agent delegation       a grant NARROWER than the subject's own — a prefix
//	                       restriction, not a second mechanism
//	ephemeral credential   the same grant with an expiry
//
// A TREE IS WRONG. Deriving access from containment cannot express an invite-only
// project, because containment would hand every ancestor's members the child.
// Containment NAMES; grants AUTHORIZE. The two are not re-braided here.
//
// Grants do not all ride in a token. The edge resolves the requested scope ONCE
// and mints the resolved path and role, so the token is constant-size and no
// decision behind the edge performs I/O. The grant SET stays in IAM, which signs
// it; the resolved DECISION travels.
package authz

import (
	"fmt"
	"strings"
	"time"
)

// Path is a location: the segments of org/workspace/project and anything below
// it. Segments are compared VERBATIM — an org is a tenancy key and must be
// injective, so folding case or whitespace here would fold two tenants into one.
type Path []string

// ParsePath reads a location from its printed form, "acme/prod/web".
//
// It is total: a path with no segments, an empty segment, or a segment carrying a
// rune that would make the identifier non-injective is not a location, and is
// refused rather than cleaned — cleaning IS the fold that merges two tenants.
func ParsePath(s string) (Path, error) {
	if s == "" {
		return nil, fmt.Errorf("authz: empty path")
	}
	p := Path(strings.Split(s, "/"))
	for _, seg := range p {
		if seg == "" {
			return nil, fmt.Errorf("authz: path %q: empty segment", s)
		}
		if HasUnsafeRune(seg) {
			return nil, fmt.Errorf("authz: path %q: segment %q is not an injective identifier", s, seg)
		}
	}
	return p, nil
}

// String prints the path in the form ParsePath reads.
func (p Path) String() string { return strings.Join(p, "/") }

// Covers reports whether p is an ancestor of, or equal to, q — the prefix test
// the whole grant model rests on.
//
// The test is SEGMENT-WISE, not textual: acme/prod does NOT cover
// acme/production. A string-prefix test would, and that is a cross-tenant read.
//
// An EMPTY path covers nothing. A zero-value scope must never be the grant that
// authorizes everything: a missing or malformed scope has to deny, or the failure
// mode of this package is a silent allow.
func (p Path) Covers(q Path) bool {
	if len(p) == 0 || len(q) == 0 || len(p) > len(q) {
		return false
	}
	for i, seg := range p {
		if seg != q[i] {
			return false
		}
	}
	return true
}

// Verb is what a subject wants to do at a path. Two verbs are what the estate
// distinguishes: IAM authorizes reads apart from writes (a GET or HEAD addresses
// its target in the query string; everything else carries a body), and cloud
// gates writes on org-admin authority while admitting members to read.
type Verb string

const (
	Read  Verb = "read"
	Write Verb = "write"
)

// VerbOf maps an HTTP method onto the verb it performs. It is the ONE mapping, so
// a caller can never disagree with IAM about whether a method writes.
func VerbOf(method string) Verb {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD":
		return Read
	}
	return Write
}

// Role is the authority a grant carries. The vocabulary is IAM's coarse
// membership role and is exactly three values (internal/schema/membership.go):
// owner, admin, member. No fourth role is defined here, because nothing in the
// estate assigns one.
type Role string

const (
	Member Role = "member"
	Admin  Role = "admin"
	Owner  Role = "owner"
)

// Admits reports whether r admits v.
//
// owner and admin are FOLDED: IAM assigns `owner` to whoever creates an org, so a
// table matching only `admin` refuses every self-serve founder their own org's
// admin surface. The fold is stated once, here.
//
// A member reads. Write authority inside a narrower location is expressed by a
// narrower grant — an invited collaborator holds admin AT acme/prod/web — not by
// a new role, which is why three roles are enough for the invite-only case.
//
// The role is folded for case and surrounding space because it is a closed
// vocabulary IAM controls, unlike an org, which is a tenant-chosen identifier and
// is therefore compared verbatim. An unknown role admits nothing.
func (r Role) Admits(v Verb) bool {
	switch Role(strings.ToLower(strings.TrimSpace(string(r)))) {
	case Member:
		return v == Read
	case Admin, Owner:
		return v == Read || v == Write
	}
	return false
}

// Grant is one access fact: Subject holds Role everywhere at or below Scope,
// until Expiry.
//
// A delegation to an agent, and a credential that expires, are this same value —
// a narrower Scope, and a set Expiry. Neither is a separate mechanism.
type Grant struct {
	Subject string
	Scope   Path
	Role    Role

	// Expiry is when the grant stops authorizing. The zero time means it does not
	// expire; an expiry that has passed authorizes nothing.
	Expiry time.Time
}

// admits reports whether g authorizes v on target at the instant now.
func (g Grant) admits(v Verb, target Path, now time.Time) bool {
	if !g.Expiry.IsZero() && !now.Before(g.Expiry) {
		return false
	}
	return g.Role.Admits(v) && g.Scope.Covers(target)
}

// Can reports whether subject may v on target under grants — the ONE predicate.
//
// True iff some grant held by subject has a scope covering target and a role
// admitting v. Fails closed: no subject, no target, or no covering grant is a
// denial, so an empty grant set authorizes nothing.
func Can(subject string, v Verb, target Path, grants []Grant) bool {
	if subject == "" || len(target) == 0 {
		return false
	}
	now := time.Now()
	for _, g := range grants {
		if g.Subject == subject && g.admits(v, target, now) {
			return true
		}
	}
	return false
}

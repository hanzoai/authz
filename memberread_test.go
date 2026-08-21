// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package authz

import "testing"

// BELONGING TO AN ORG LETS YOU SEE WHAT IT CONTAINS.
//
// The tenant rule at the tail of CanEntity admits a non-admin person exactly one
// entity — their own user row — so before this clause a plain member could not list
// the projects of their OWN org, and a console's org switcher listed orgs whose
// projects it then could not fetch. Belonging is also a SET: an account lives in one
// tenant while the orgs a person works in are many, so the home org is not the
// question. The organizations branch already grants a member the read of the org
// ROW; this is the same authority applied to what the org contains.
//
// The width is the whole question, so the refusals below carry more weight than the
// admission: read only, two kinds only, and only for an org this principal is
// actually in. Widening the verb would let anyone ever added to an org delete its
// projects; widening the kinds would reach users, certs and applications, which
// belonging does not entitle you to.

func TestMemberReadsWhatTheirOrgsContain(t *testing.T) {
	none := allow(nil)
	// Both accounts live in acme; only the first also belongs to beta.
	member := person("acme", "alice", false, map[string]Role{"acme": Member, "beta": Member})
	stranger := person("acme", "bob", false, map[string]Role{"acme": Member})

	for _, tc := range []struct {
		name string
		p    *Principal
		v    Verb
		e    Entity
		want bool
	}{
		// The admission, and its home-org control.
		{"a member reads the projects of an org they belong to",
			member, Read, Entity{Kind: "projects", Owner: "beta"}, true},
		{"a member reads the workspaces of an org they belong to",
			member, Read, Entity{Kind: "workspaces", Owner: "beta"}, true},
		// This one is not a control: the tenant rule admits a non-admin exactly one
		// entity, their own user row, so a plain member could not read their OWN
		// org's projects either. Both orgs travel the same clause.
		{"a member reads the projects of the org they live in",
			member, Read, Entity{Kind: "projects", Owner: "acme"}, true},

		// THE VERB. Belonging is not authority to change anything.
		{"a member does NOT write the projects of an org they belong to",
			member, Write, Entity{Kind: "projects", Owner: "beta"}, false},
		{"a member does NOT write its workspaces either",
			member, Write, Entity{Kind: "workspaces", Owner: "beta"}, false},

		// THE KIND. Belonging says nothing about who else is in the org, what
		// signs its tokens, or which clients it has registered.
		{"a member does NOT read the users of an org they belong to",
			member, Read, Entity{Kind: "users", Owner: "beta"}, false},
		{"a member does NOT read its certs",
			member, Read, Entity{Kind: "certs", Owner: "beta"}, false},
		{"a member does NOT read its applications",
			member, Read, Entity{Kind: "applications", Owner: "beta"}, false},

		// THE MEMBERSHIP. This is the tenant boundary and it did not move.
		{"a stranger does NOT read another org's projects",
			stranger, Read, Entity{Kind: "projects", Owner: "beta"}, false},
		{"an unowned entity is refused rather than read by anybody",
			member, Read, Entity{Kind: "projects", Owner: ""}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.CanEntity(tc.v, tc.e, none); got != tc.want {
				t.Errorf("CanEntity(%s, %+v) = %v, want %v", tc.v, tc.e, got, tc.want)
			}
		})
	}
}

// AN APP DOES NOT REACH THIS CLAUSE. A confidential client's entire authority is
// its capability allowlist, so a client credential that somehow carried a
// membership set must not inherit a person's reach — the App branch answers first.
func TestAnAppDoesNotBorrowAMembership(t *testing.T) {
	c := app("acme", "hanzo-console", "cert-hanzo")
	c.Orgs = []Membership{{Org: "beta", Role: Admin}}
	if c.Principal().CanEntity(Read, Entity{Kind: "projects", Owner: "beta"}, allow(nil)) {
		t.Error("an app principal read another org's projects on the strength of a membership claim")
	}
}

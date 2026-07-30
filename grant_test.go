package authz

import (
	"testing"
	"time"
)

// path is a test helper: a location that must parse. A path that does not parse is
// a bug in the test, not a case under test.
func path(t *testing.T, s string) Path {
	t.Helper()
	p, err := ParsePath(s)
	if err != nil {
		t.Fatalf("ParsePath(%q): %v", s, err)
	}
	return p
}

// The prefix test is SEGMENT-WISE. A textual prefix test would have acme/prod
// cover acme/production, which is a cross-tenant read one tier down.
func TestCoversIsSegmentWise(t *testing.T) {
	for _, c := range []struct {
		scope, target string
		want          bool
	}{
		{"acme", "acme", true},
		{"acme", "acme/prod", true},
		{"acme", "acme/prod/web", true},
		{"acme/prod", "acme/prod/web/site/landing", true},

		{"acme/prod", "acme/production", false},       // the textual-prefix trap
		{"acme/prod", "acme/production/web", false},   // and one tier deeper
		{"acme", "acmecorp", false},                   // same trap at the org tier
		{"acme", "acmecorp/prod", false},              //
		{"acme/prod/web", "acme/prod", false},         // a child never covers its parent
		{"acme/prod", "other/prod", false},            // a sibling tenant
		{"acme/dev", "acme/prod", false},              //
		{"acme/prod/web", "acme/prod/website", false}, // and at the project tier
	} {
		if got := path(t, c.scope).Covers(path(t, c.target)); got != c.want {
			t.Errorf("%q.Covers(%q) = %v, want %v", c.scope, c.target, got, c.want)
		}
	}
}

// An empty scope must cover NOTHING. A zero-value Grant authorizing everything
// makes the failure mode of this package a silent allow.
func TestEmptyPathCoversNothing(t *testing.T) {
	if (Path{}).Covers(path(t, "acme/prod")) {
		t.Error("an empty scope covered a real path")
	}
	if Path(nil).Covers(path(t, "acme")) {
		t.Error("a nil scope covered a real path")
	}
	if path(t, "acme").Covers(Path{}) {
		t.Error("a real scope covered an empty target")
	}
	if Can("u", Read, Path{}, []Grant{{Subject: "u", Scope: path(t, "acme"), Role: Owner}}) {
		t.Error("Can authorized an empty target")
	}
}

// A path is refused, never cleaned: cleaning is the fold that merges two tenants.
func TestParsePathRefusesNonInjective(t *testing.T) {
	for _, s := range []string{"", "/", "acme//prod", "/acme", "acme/", "acme prod", "acme​/prod", "acme\t"} {
		if p, err := ParsePath(s); err == nil {
			t.Errorf("ParsePath(%q) = %v, want error", s, p)
		}
	}
	if got := path(t, "acme/prod/web").String(); got != "acme/prod/web" {
		t.Errorf("String() = %q", got)
	}
}

// An INVITE-ONLY project: a grant at acme/prod/web authorizes that project and
// everything under it, and NOTHING above it. This is the arrangement a containment
// tree cannot express, and the reason access is a grant at a prefix rather than
// something derived from the location hierarchy.
func TestInviteOnlyProjectAuthorizesNothingAbove(t *testing.T) {
	grants := []Grant{{Subject: "guest", Scope: path(t, "acme/prod/web"), Role: Admin}}

	for _, at := range []string{"acme/prod/web", "acme/prod/web/site/landing"} {
		if !Can("guest", Write, path(t, at), grants) {
			t.Errorf("invited collaborator refused at %q", at)
		}
	}
	for _, above := range []string{"acme", "acme/prod", "acme/prod/api", "acme/dev"} {
		if Can("guest", Read, path(t, above), grants) {
			t.Errorf("a grant at acme/prod/web authorized %q", above)
		}
	}
}

// DELEGATION is a prefix restriction, not a second mechanism: a user holding acme
// hands an agent acme/prod/web, and the agent reaches only that.
func TestDelegationIsNarrowerThanTheSubjectOwn(t *testing.T) {
	user := Grant{Subject: "z", Scope: path(t, "acme"), Role: Owner}
	agent := Grant{Subject: "agent", Scope: path(t, "acme/prod/web"), Role: Admin}
	grants := []Grant{user, agent}

	if !Can("z", Write, path(t, "acme/dev/api"), grants) {
		t.Error("the delegating user lost authority over their own org")
	}
	if !Can("agent", Write, path(t, "acme/prod/web"), grants) {
		t.Error("the agent was refused its delegated project")
	}
	for _, wider := range []string{"acme", "acme/prod", "acme/dev/api"} {
		if Can("agent", Read, path(t, wider), grants) {
			t.Errorf("the agent reached %q, wider than its delegation", wider)
		}
	}
	// A grant is bound to its subject: the agent's grant never authorizes anyone
	// else, and the user's never authorizes the agent.
	if Can("stranger", Read, path(t, "acme/prod/web"), grants) {
		t.Error("a grant authorized a subject it does not name")
	}
}

// An EXPIRED grant authorizes nothing. An ephemeral credential is this same value
// with Expiry set, so expiry has to be part of the one predicate.
func TestExpiredGrantAuthorizesNothing(t *testing.T) {
	target := path(t, "acme/prod/web")
	live := []Grant{{Subject: "agent", Scope: target, Role: Admin, Expiry: time.Now().Add(time.Hour)}}
	dead := []Grant{{Subject: "agent", Scope: target, Role: Admin, Expiry: time.Now().Add(-time.Second)}}
	never := []Grant{{Subject: "agent", Scope: target, Role: Admin}}

	if !Can("agent", Write, target, live) {
		t.Error("an unexpired grant was refused")
	}
	if !Can("agent", Write, target, never) {
		t.Error("a grant with no expiry was refused")
	}
	if Can("agent", Read, target, dead) {
		t.Error("an EXPIRED grant authorized a read")
	}
}

// Three role names, two authority levels. owner and admin are folded because IAM
// assigns owner to whoever creates an org; a member reads. An unknown role admits
// nothing, so a typo in the data denies rather than allows.
func TestRoleAdmits(t *testing.T) {
	for _, c := range []struct {
		role              Role
		read, write, junk bool
	}{
		{Member, true, false, false},
		{Admin, true, true, false},
		{Owner, true, true, false},
		{"OWNER", true, true, false}, // the role is a closed vocabulary IAM controls
		{" admin ", true, true, false},
		{"", false, false, false},
		{"viewer", false, false, false}, // a role nothing in the estate assigns
		{"superuser", false, false, false},
	} {
		if got := c.role.Admits(Read); got != c.read {
			t.Errorf("Role(%q).Admits(Read) = %v, want %v", c.role, got, c.read)
		}
		if got := c.role.Admits(Write); got != c.write {
			t.Errorf("Role(%q).Admits(Write) = %v, want %v", c.role, got, c.write)
		}
		if got := c.role.Admits("delete"); got != c.junk {
			t.Errorf("Role(%q).Admits(unknown verb) = %v, want %v", c.role, got, c.junk)
		}
	}
}

// A member reads and does not write — that difference is the whole reason two
// verbs exist, and it is how cloud gates writes on org-admin authority.
func TestMemberReadsAdminWrites(t *testing.T) {
	at := path(t, "acme/prod")
	member := []Grant{{Subject: "u", Scope: path(t, "acme"), Role: Member}}
	if !Can("u", Read, at, member) {
		t.Error("an org member could not read")
	}
	if Can("u", Write, at, member) {
		t.Error("an org MEMBER was authorized to write")
	}
}

func TestVerbOf(t *testing.T) {
	for m, want := range map[string]Verb{
		"GET": Read, "HEAD": Read, "get": Read,
		"POST": Write, "PUT": Write, "PATCH": Write, "DELETE": Write, "": Write,
	} {
		if got := VerbOf(m); got != want {
			t.Errorf("VerbOf(%q) = %q, want %q", m, got, want)
		}
	}
}

// A membership IS a grant at that org's path, so the two representations of
// org-wide access cannot disagree.
func TestClaimsGrantsProjectMemberships(t *testing.T) {
	c := &Claims{
		Owner:             "acme",
		PreferredUsername: "z",
		Orgs:              []Membership{{Org: "acme", Role: Admin}, {Org: "other", Role: Member}, {Org: "bad org", Role: Owner}},
	}
	c.Subject = "acme/z"

	if !c.Can(Write, path(t, "acme/prod/web"), nil) {
		t.Error("an org admin was refused a write inside their own org")
	}
	if !c.Can(Read, path(t, "other/prod"), nil) {
		t.Error("a member of a second org was refused a read there")
	}
	if c.Can(Write, path(t, "other/prod"), nil) {
		t.Error("a MEMBER of a second org was authorized to write there")
	}
	if c.Can(Read, path(t, "unrelated/prod"), nil) {
		t.Error("a read was authorized in an org with no membership")
	}
	// A non-injective org yields no grant rather than a cleaned one.
	for _, g := range c.Grants() {
		if HasUnsafeRune(g.Scope.String()) {
			t.Errorf("a non-injective org produced a grant: %q", g.Scope)
		}
	}
	// The extra grant set carries everything narrower than an org.
	invite := []Grant{{Subject: "acme/z", Scope: path(t, "third/prod/web"), Role: Admin}}
	if !c.Can(Write, path(t, "third/prod/web"), invite) {
		t.Error("a supplied grant did not authorize its own scope")
	}
	if c.Can(Read, path(t, "third/prod"), invite) {
		t.Error("a supplied project grant authorized its parent workspace")
	}
}

// The platform operator acts anywhere, and only as a HUMAN: an admin-org machine
// identity is not a cross-tenant principal.
func TestPlatformSudoIsCrossTenantOnlyForHumans(t *testing.T) {
	// The human carries the home-org membership IAM signs into every user token; the
	// machine carries none, which is the shape IAM's client_credentials grant mints.
	human := &Claims{Owner: AdminOrg, PreferredUsername: "z",
		Orgs: []Membership{{Org: AdminOrg, Role: Admin}}}
	machine := &Claims{Owner: AdminOrg, PreferredUsername: "kms", TokenType: "access-token"}

	if !human.Can(Write, path(t, "victim/prod"), nil) {
		t.Error("the platform operator was refused a cross-tenant write")
	}
	if machine.Can(Read, path(t, "victim/prod"), nil) {
		t.Error("an admin-org MACHINE was authorized cross-tenant")
	}
	var nilClaims *Claims
	if nilClaims.Can(Read, path(t, "acme"), nil) {
		t.Error("nil claims authorized a read")
	}
}

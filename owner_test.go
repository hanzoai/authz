package authz

import "testing"

// Only an owner, or a SuperAdmin, owns an org. An admin administers it and owns
// nothing; a machine and a stranger own nothing; the admin org is the
// SuperAdmins' alone, whatever role a membership row there claims.
func TestOwnerOf(t *testing.T) {
	owner := &Principal{Org: "acme", User: "ann", Orgs: map[string]Role{"acme": Owner, "beta": " OWNER "}}
	admin := &Principal{Org: "acme", User: "bob", Admin: true, Orgs: map[string]Role{"acme": Admin}}
	member := &Principal{Org: "acme", User: "cy", Orgs: map[string]Role{"acme": Member}}
	brand := &Principal{Org: "hanzo", User: "z", Admin: true, Orgs: map[string]Role{AdminOrg: Owner}}
	super := &Principal{Org: AdminOrg, User: "z", Sudo: true}
	app := &Principal{App: &App{Name: "acme-console", Owner: AdminOrg}, Org: "acme", Orgs: map[string]Role{"acme": Owner}}
	bot := &Principal{Org: "acme", User: "bot", Machine: true, Orgs: map[string]Role{"acme": Owner}}
	for _, c := range []struct {
		name string
		p    *Principal
		org  string
		want bool
	}{
		{"owner", owner, "acme", true},
		{"owner by folded role", owner, "beta", true},
		{"owner elsewhere", owner, "gamma", false},
		{"admin", admin, "acme", false},
		{"member", member, "acme", false},
		{"brand owner row in the admin org", brand, AdminOrg, false},
		{"superadmin anywhere", super, "acme", true},
		{"superadmin in the admin org", super, AdminOrg, true},
		{"application", app, "acme", false},
		{"service account", bot, "acme", false},
		{"no org", owner, "", false},
		{"nil", nil, "acme", false},
	} {
		if got := c.p.OwnerOf(c.org); got != c.want {
			t.Errorf("%s: OwnerOf(%q) = %v, want %v", c.name, c.org, got, c.want)
		}
	}
}

// A token with no orgs is a machine's, and its principal owns nothing whatever
// its org says.
func TestAProgramsTokenOwnsNothing(t *testing.T) {
	c := &Claims{Owner: "acme"}
	c.Subject = "acme/acme-worker"
	if p := c.Principal(); !p.Machine || p.OwnerOf("acme") {
		t.Fatalf("a program's principal: Machine=%v OwnerOf=%v", p.Machine, p.OwnerOf("acme"))
	}
}

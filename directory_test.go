package authz

import "testing"

// A brand's directory is every customer's home and no one's tenant. These hold
// the three things that make it so: a request never acts in it, nobody
// administers or is granted it, and the org a customer acts in when they select
// none is their personal org, which IAM lists right after the home.

func TestEachBrandHasOneDirectoryNoCustomerFounds(t *testing.T) {
	for brand, dir := range map[string]string{"hanzo": "hanzo-id", "lux": "lux-id", "zoo": "zoo-id", "pars": "pars-id"} {
		if got := DirectoryOf(brand); got != dir {
			t.Errorf("DirectoryOf(%q) = %q, want %q", brand, got, dir)
		}
		if !IsDirectory(dir) || !IsHeldOrg(dir) || !IsPlatformOrg(dir) {
			t.Errorf("%s: directory %v, held %v, platform %v; want all three", dir, IsDirectory(dir), IsHeldOrg(dir), IsPlatformOrg(dir))
		}
	}
	for _, org := range []string{"acme", "hanzo", "admin", "adnexus", ""} {
		if IsDirectory(org) || DirectoryOf(org+"-x") != "" {
			t.Errorf("%q reads as a directory", org)
		}
	}
}

func TestADirectoryCustomerActsInTheirPersonalOrg(t *testing.T) {
	c := &Claims{PreferredUsername: "alice", IsAdmin: true, Orgs: []Membership{
		{Org: "hanzo-id", Role: Member}, {Org: "alice", Role: Owner}, {Org: "acme", Role: Member},
	}}
	c.Subject = "uuid-alice"
	if c.Home() != "hanzo-id" {
		t.Fatalf("Home() = %q, want the directory: it is who she is", c.Home())
	}
	if got := c.Default(); got != "alice" {
		t.Fatalf("Default() = %q, want the personal org alice", got)
	}
	if got := c.Tenancy(); len(got) != 2 || got[0].Org != "alice" || got[1].Org != "acme" {
		t.Fatalf("Tenancy() = %+v, want alice then acme, never the directory", got)
	}
	for _, sel := range []string{"", "hanzo-id", "lux", "nowhere"} {
		if org, switched := c.EffectiveOrg(sel); org != "alice" || switched {
			t.Errorf("EffectiveOrg(%q) = %q %v, want alice, unswitched", sel, org, switched)
		}
	}
	if org, switched := c.EffectiveOrg("acme"); org != "acme" || !switched {
		t.Errorf("EffectiveOrg(acme) = %q %v, want the team she belongs to", org, switched)
	}
	if c.LedgerOrg("") != "alice" || c.LedgerOrg("acme") != "acme" {
		t.Errorf("LedgerOrg = %q / %q, want alice then acme", c.LedgerOrg(""), c.LedgerOrg("acme"))
	}
	if c.OrgAdmin("hanzo-id") {
		t.Error("a customer administers the directory")
	}
	if !c.OrgAdmin("alice") || c.OrgAdmin("acme") {
		t.Errorf("OrgAdmin alice=%v acme=%v, want true then false", c.OrgAdmin("alice"), c.OrgAdmin("acme"))
	}
	for _, g := range c.Grants() {
		if IsDirectory(g.Scope[0]) {
			t.Errorf("a grant names the directory: %+v", g)
		}
	}
	if c.Sudo() {
		t.Error("a directory customer is a SuperAdmin")
	}
}

// An account whose membership set opens nothing past the directory has no org to
// act in, so every org gate fails closed rather than acting in the directory.
func TestADirectoryAloneOpensNothing(t *testing.T) {
	c := &Claims{PreferredUsername: "bob", Orgs: []Membership{{Org: "hanzo-id", Role: Member}}}
	c.Subject = "uuid-bob"
	if c.Default() != "" {
		t.Fatalf("Default() = %q, want empty", c.Default())
	}
	if org, _ := c.EffectiveOrg("hanzo-id"); org != "" {
		t.Fatalf("EffectiveOrg(hanzo-id) = %q, want empty", org)
	}
	if len(c.Grants()) != 0 {
		t.Fatalf("Grants() = %+v, want none", c.Grants())
	}
}

// Everyone else is untouched: a home that is not a directory is the default.
func TestATenantHomeStaysTheDefault(t *testing.T) {
	c := &Claims{PreferredUsername: "carol", Orgs: []Membership{{Org: "acme", Role: Owner}, {Org: "beta", Role: Member}}}
	c.Subject = "uuid-carol"
	if c.Default() != "acme" {
		t.Fatalf("Default() = %q, want acme", c.Default())
	}
	if org, _ := c.EffectiveOrg(""); org != "acme" {
		t.Fatalf("EffectiveOrg('') = %q, want acme", org)
	}
}

// The orgs the platform funds by name are held — no customer founds one — and run
// by their customers, not the platform.
func TestFundedOrgsAreHeldAndTheirCustomers(t *testing.T) {
	for _, org := range []string{"adnexus", "bootnode", "osage"} {
		if !IsHeldOrg(org) || IsPlatformOrg(org) {
			t.Errorf("%s: held %v, platform %v; want held and not the platform's", org, IsHeldOrg(org), IsPlatformOrg(org))
		}
	}
	for _, org := range []string{"hanzo", "lux", "zoo", "pars", "platform", "hanzoai", "admin", "app", "built-in"} {
		if !IsPlatformOrg(org) {
			t.Errorf("%s is not the platform's", org)
		}
	}
}

// A directory customer projected onto the registry decision reaches no row of the
// directory but their own: not its other users, not its org row, and administers
// nothing there. A SuperAdmin still reaches it.
func TestADirectoryCustomerReachesOnlyTheirOwnRow(t *testing.T) {
	c := &Claims{PreferredUsername: "alice", IsAdmin: true, Orgs: []Membership{
		{Org: "hanzo-id", Role: Owner}, {Org: "alice", Role: Owner},
	}}
	c.Subject = "uuid-alice"
	p := c.Principal()
	if p.MemberOf("hanzo-id") || p.AdminOf("hanzo-id") || p.OwnerOf("hanzo-id") {
		t.Fatalf("member %v admin %v owner %v of the directory, want none", p.MemberOf("hanzo-id"), p.AdminOf("hanzo-id"), p.OwnerOf("hanzo-id"))
	}
	for _, e := range []Entity{
		{Kind: "users", Owner: "hanzo-id", Name: "bob"},
		{Kind: "users", Owner: "hanzo-id"},
		{Kind: "keys", Owner: "hanzo-id"},
		{Kind: "projects", Owner: "hanzo-id"},
		{Kind: "organizations", Owner: AdminOrg, Name: "hanzo-id"},
	} {
		if p.CanEntity(Read, e, nil) || p.CanEntity(Write, e, nil) {
			t.Errorf("a directory customer reaches %+v", e)
		}
	}
	if !p.CanEntity(Read, Entity{Kind: "users", Owner: "hanzo-id", Name: "alice"}, nil) {
		t.Error("a directory customer cannot read their own row")
	}
	if !p.AdminOf("alice") || !p.CanEntity(Write, Entity{Kind: "keys", Owner: "alice", Name: "k"}, nil) {
		t.Error("a directory customer does not run their personal org")
	}
	op := (&Claims{PreferredUsername: "z", Orgs: []Membership{{Org: AdminOrg, Role: Admin}}}).Principal()
	if !op.MemberOf("hanzo-id") || !op.CanEntity(Read, Entity{Kind: "users", Owner: "hanzo-id", Name: "bob"}, nil) {
		t.Error("a SuperAdmin does not reach the directory")
	}
}

// A plain member of an org the platform runs — a customer who landed in a brand
// org — is not its tenant: the org opens nothing to them, so they act in no org
// of the platform's, and the registry decision reaches none of its rows. Its
// admins, its machines and a SuperAdmin are unchanged.
func TestABrandOrgOpensOnlyToThoseWhoRunIt(t *testing.T) {
	guest := &Claims{PreferredUsername: "eve", Orgs: []Membership{{Org: "hanzo", Role: Member}, {Org: "eve-co", Role: Owner}}}
	guest.Subject = "uuid-eve"
	if guest.Default() != "eve-co" {
		t.Fatalf("Default() = %q, want her own org eve-co", guest.Default())
	}
	if got := guest.Tenancy(); len(got) != 1 || got[0].Org != "eve-co" {
		t.Fatalf("Tenancy() = %+v, want eve-co alone", got)
	}
	if org, _ := guest.EffectiveOrg("hanzo"); org != "eve-co" {
		t.Fatalf("EffectiveOrg(hanzo) = %q, want the switch refused", org)
	}
	for _, g := range guest.Grants() {
		if g.Scope[0] == "hanzo" {
			t.Fatalf("a plain member is granted the brand org: %+v", g)
		}
	}
	alone := &Claims{PreferredUsername: "mal", Orgs: []Membership{{Org: "zoo", Role: Member}}}
	alone.Subject = "uuid-mal"
	if alone.Default() != "" {
		t.Fatalf("a plain member with no org of their own acts in %q", alone.Default())
	}
	if p := alone.Principal(); p.MemberOf("zoo") || p.CanEntity(Read, Entity{Kind: "projects", Owner: "zoo"}, nil) {
		t.Fatal("a plain member reaches the brand org's rows")
	}

	staff := &Claims{PreferredUsername: "lead", IsAdmin: true, Orgs: []Membership{{Org: "hanzo", Role: Admin}}}
	staff.Subject = "uuid-lead"
	if staff.Default() != "hanzo" || !staff.Principal().MemberOf("hanzo") {
		t.Fatalf("the brand org's admin does not act in it: %q", staff.Default())
	}
	op := &Claims{PreferredUsername: "z", Orgs: []Membership{{Org: AdminOrg, Role: Admin}, {Org: "hanzo", Role: Member}}}
	op.Subject = "uuid-z"
	if org, _ := op.EffectiveOrg("hanzo"); org != "hanzo" {
		t.Fatalf("a SuperAdmin cannot act in the brand org: %q", org)
	}
	bot := &Principal{Org: "hanzo", User: "hanzo-bot", Machine: true}
	if !bot.MemberOf("hanzo") {
		t.Fatal("the brand org's own machine is not its member")
	}
	// The same machine, as the claims its client_credentials token carries, acts in
	// its org by default: the platform's services keep their tenant.
	program := &Claims{Owner: "hanzo", TokenType: "access-token", Type: Program, Orgs: []Membership{{Org: "hanzo", Role: Member}}}
	program.Subject = "uuid-bot"
	if program.Default() != "hanzo" {
		t.Fatalf("the brand org's machine acts in %q, want hanzo", program.Default())
	}
	// A machine of another org that holds a plain membership of the brand org is a
	// plain member of it, as a person is.
	stranger := &Claims{Owner: "evil", TokenType: "access-token", Type: Program, Orgs: []Membership{{Org: "evil", Role: Admin}, {Org: "lux", Role: Member}}}
	stranger.Subject = "uuid-evil-bot"
	if org, _ := stranger.EffectiveOrg("lux"); org == "lux" {
		t.Fatal("another org's machine acts in the brand org")
	}
	if (&Principal{Org: "evil", User: "evil-bot", Machine: true, Orgs: map[string]Role{"lux": Member}}).MemberOf("lux") {
		t.Fatal("another org's machine reaches the brand org's rows")
	}
	// A customer org the platform funds by name is its customers' tenant as any is.
	cust := &Claims{PreferredUsername: "ann", Orgs: []Membership{{Org: "adnexus", Role: Member}}}
	cust.Subject = "uuid-ann"
	if cust.Default() != "adnexus" || !cust.Principal().MemberOf("adnexus") {
		t.Fatal("a member of a funded customer org is refused it")
	}
}

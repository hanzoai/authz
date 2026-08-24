package authz

import "testing"

// allow builds an Env from a literal — the capability allowlist as DATA, supplied
// by the caller. The decision never reads the process environment, which is what
// keeps it free of config; a test supplies a map where a server supplies os.Getenv.
func allow(m map[string]string) Env {
	return func(name string) string { return m[name] }
}

// app is a confidential client principal: the (owner, name) of its application row
// and the cert that row references.
func app(owner, name, cert string) *Claims {
	return &Claims{Owner: owner, App: &App{Name: name, Owner: owner, Cert: cert}}
}

// AN APP PRINCIPAL IS NEVER ADMIN AND NEVER SUDO. Its entire authority is the
// capability allowlist, so a leaked client credential can neither read another
// tenant nor touch signing material. This is the "every client credential is a
// global admin" hole, held closed.
func TestAppIsNeverAdminNorSudo(t *testing.T) {
	// Every flag a token could carry is set the wrong way on purpose: the app's home
	// org IS the reserved admin org and IsAdmin is on.
	c := &Claims{
		Owner:   AdminOrg,
		IsAdmin: true,
		App:     &App{Name: "hanzo-console", Owner: AdminOrg, Cert: "cert-hanzo"},
	}
	// …and the token even carries a membership set, so the App statement is what
	// closes this on its own rather than leaning on the membership signal.
	c.TokenType = "access-token"
	c.Orgs = []Membership{{Org: AdminOrg, Role: Owner}}

	if c.Sudo() {
		t.Error("an app principal may act cross-tenant")
	}
	if c.OrgAdmin(AdminOrg) {
		t.Error("an app principal administers an org")
	}
	if c.Can(Write, Path{"victim", "prod"}, nil) {
		t.Error("an app principal was authorized a cross-tenant write")
	}
	// Not even its own org: an app's authority is capabilities, not membership.
	if c.Can(Write, Path{AdminOrg}, nil) {
		t.Error("an app principal was authorized by membership")
	}
	// The registry decision agrees: signing material stays out of reach whatever
	// the allowlist says, because no capability maps to certs.
	env := allow(map[string]string{"IAM_ORG_ADMIN_APPS": "hanzo-console", "IAM_USER_ADMIN_APPS": "hanzo-console"})
	for _, kind := range []string{"certs", "providers", "tokens", "syncers", "webhooks"} {
		if c.CanEntity(Write, Entity{Kind: kind, Owner: AdminOrg, Name: "x"}, env) {
			t.Errorf("an app principal wrote platform-owned %s", kind)
		}
	}
}

// A CAPABILITY NEEDS THE RESERVED PLATFORM SIGNING OWNER. The allowlist keys on
// the application NAME, so without the owner-pin any tenant that registers
// <theirOrg>/hanzo-console inherits the platform console's grants.
func TestCapabilityNeedsAReservedSigningOwner(t *testing.T) {
	env := allow(map[string]string{"IAM_ORG_ADMIN_APPS": "hanzo-console", "IAM_USER_ADMIN_APPS": "hanzo-console"})

	for _, owner := range signingOwners {
		if !app(owner, "hanzo-console", "").Holds(CapOrgAdmin, env) {
			t.Errorf("the allow-listed console owned by %q holds no capability", owner)
		}
	}
	// The spoof: same allow-listed NAME, the tenant's own owner. The pin denies
	// before any name match, so the signup -> register-app -> Basic-auth
	// escalation is inert.
	spoof := app("evil", "hanzo-console", "")
	if spoof.Holds(CapOrgAdmin, env) {
		t.Error("a tenant-owned app spoofing the console NAME holds a capability")
	}
	if spoof.CanEntity(Write, Entity{Kind: "organizations", Owner: AdminOrg, Name: "victim"}, env) {
		t.Error("a spoofed console wrote the tenant registry")
	}
	if spoof.CanEntity(Write, Entity{Kind: "users", Owner: "victim", Name: "x"}, env) {
		t.Error("a spoofed console wrote another tenant's user")
	}
	// The genuine console does hold what it is listed for — cross-tenant by design,
	// because a platform console onboards any customer org.
	console := app(AdminOrg, "hanzo-console", "")
	if !console.CanEntity(Write, Entity{Kind: "users", Owner: "orgb", Name: "x"}, env) {
		t.Error("the platform console lost the user-admin capability it is listed for")
	}
	if !console.CanEntity(Write, Entity{Kind: "organizations", Owner: AdminOrg, Name: "hanzo"}, env) {
		t.Error("the platform console lost the org-admin capability it is listed for")
	}
	// A user under a RESERVED owner is never writable by an app: provision, never
	// promote — no capability lands a principal in a platform org.
	for _, reserved := range []string{AdminOrg, "built-in", serviceOrg} {
		if console.CanEntity(Write, Entity{Kind: "users", Owner: reserved, Name: "x"}, env) {
			t.Errorf("the console landed a user under the reserved owner %q", reserved)
		}
	}
	// Fail-secure: an unset allowlist, an empty one, an unmapped kind, and a nil
	// lookup each deny.
	for name, e := range map[string]Env{
		"unset": allow(nil),
		"empty": allow(map[string]string{"IAM_ORG_ADMIN_APPS": ""}),
		"other": allow(map[string]string{"IAM_ORG_ADMIN_APPS": "someone-else"}),
		"nil":   nil,
	} {
		if console.Holds(CapOrgAdmin, e) {
			t.Errorf("an app held a capability with a %s allowlist", name)
		}
	}
	// A human holds every capability vacuously — this gate is about confidential
	// clients, and a human's authority is decided by the registry policy.
	human := &Claims{Owner: "acme", PreferredUsername: "alice"}
	if !human.Holds(CapKeyMint, allow(nil)) {
		t.Error("a human was refused by the app capability gate")
	}
}

// AN APP SELF-READS ITS OWN ROW AND ITS OWN CERT, AND NOTHING ELSE. A relying
// party bootstraps by reading its application and then the cert that application
// names; both are pinned to the row it authenticated as.
func TestAppSelfReadsOnlyItsOwnRowAndCert(t *testing.T) {
	env := allow(nil) // no capability at all: the self-read clauses are the whole authority
	c := app(AdminOrg, "hanzo-cloud", "cert-hanzo")
	c.Owner = "hanzo" // the tenant it SERVES, distinct from the owner of its row

	read := func(kind, owner, name string) bool {
		return c.CanEntity(Read, Entity{Kind: kind, Owner: owner, Name: name}, env)
	}

	if !read("applications", AdminOrg, "hanzo-cloud") {
		t.Error("an app cannot read its own registration — every deploy 403s on its own bootstrap")
	}
	// Both halves of the key must match, so this is self-read and not "apps may
	// read applications".
	if read("applications", "hanzo", "hanzo-cloud") {
		t.Error("the same NAME under a tenant owner is a different row and was admitted")
	}
	if read("applications", AdminOrg, "hanzo-console") {
		t.Error("a sibling application in the same owner was admitted")
	}
	if read("applications", "", "hanzo-cloud") {
		t.Error("an empty owner matched the self-read")
	}
	// Never a WRITE to its own row: that would let a client widen its own redirect
	// URIs or grant types.
	if c.CanEntity(Write, Entity{Kind: "applications", Owner: AdminOrg, Name: "hanzo-cloud"}, env) {
		t.Error("self-read became self-write")
	}

	// THE ONE CERT ITS ROW NAMES. The owner half varies by caller — <servedOrg>/,
	// a hardcoded admin/, or a bare ?id= with no owner — so the NAME is the gate.
	for _, owner := range []string{"", AdminOrg, "hanzo"} {
		if !read("certs", owner, "cert-hanzo") {
			t.Errorf("an app was refused the cert its own row names (owner %q)", owner)
		}
	}
	if read("certs", AdminOrg, "cert-lux") {
		t.Error("an app walked to another brand's signing cert")
	}
	if read("certs", "victim", "cert-hanzo") {
		t.Error("an app read its cert under an owner that is neither its row's nor the org it serves")
	}
	if c.CanEntity(Write, Entity{Kind: "certs", Owner: AdminOrg, Name: "cert-hanzo"}, env) {
		t.Error("an app WROTE a signing cert")
	}
	// An app whose row names no cert reaches none, so an empty Cert never matches
	// an empty requested name.
	if app(AdminOrg, "hanzo-cloud", "").CanEntity(Read, Entity{Kind: "certs", Owner: AdminOrg, Name: ""}, env) {
		t.Error("an app with no cert on its row read a cert")
	}
}

// An org's OWN PaaS machine identity reads that org's projects, and nothing else —
// the grant that lets cloud resolve a tenant's projects from the canonical store
// instead of a second embedded database. Each wall of it gets a negative.
func TestKMSMachineReadsOnlyItsOwnOrgProjects(t *testing.T) {
	env := allow(nil)
	acme := app(AdminOrg, "acme-platform-kms", "")
	acme.Owner = "acme"

	if !acme.CanEntity(Read, Entity{Kind: "projects", Owner: "acme", Name: "web"}, env) {
		t.Fatal("the org's own platform-kms identity cannot read the org's projects")
	}
	if !acme.CanEntity(Read, Entity{Kind: "projects", Owner: "acme"}, env) {
		t.Fatal("listing the org's projects is the same read")
	}
	if acme.CanEntity(Read, Entity{Kind: "projects", Owner: "rival", Name: "web"}, env) {
		t.Fatal("one tenant's identity walked another's project list")
	}
	if acme.CanEntity(Write, Entity{Kind: "projects", Owner: "acme", Name: "web"}, env) {
		t.Fatal("the grant is read-only and admitted a write")
	}
	if acme.CanEntity(Read, Entity{Kind: "projects", Name: "web"}, env) {
		t.Fatal("an owner-less project read was admitted")
	}
	for _, name := range []string{"acme-console", "rival-platform-kms", "platform-kms"} {
		p := app(AdminOrg, name, "")
		p.Owner = "acme"
		if p.CanEntity(Read, Entity{Kind: "projects", Owner: "acme", Name: "web"}, env) {
			t.Fatalf("app %q inherited the platform-kms grant", name)
		}
	}
}

// The registry's three human scopes, never conflated: platform sudo is the only
// cross-tenant one; an org admin manages its OWN org; a regular user self-READS
// its own record and cannot write it (a write would carry isAdmin — self-promotion).
func TestRegistryHumanScopes(t *testing.T) {
	env := allow(nil)
	// Each carries the home-org membership every user token IAM signs, first entry.
	sudo := &Claims{Owner: AdminOrg, PreferredUsername: "z",
		Orgs: []Membership{{Org: AdminOrg, Role: Admin}}}
	orgAdmin := &Claims{Owner: "acme", PreferredUsername: "boss", IsAdmin: true,
		Orgs: []Membership{{Org: "acme", Role: Admin}}}
	user := &Claims{Owner: "acme", PreferredUsername: "alice",
		Orgs: []Membership{{Org: "acme", Role: Member}}}

	if !sudo.CanEntity(Write, Entity{Kind: "certs", Owner: AdminOrg, Name: "cert-hanzo"}, env) {
		t.Error("platform sudo cannot write platform trust material")
	}
	if !orgAdmin.CanEntity(Write, Entity{Kind: "users", Owner: "acme", Name: "alice"}, env) {
		t.Error("an org admin cannot manage its own org's user")
	}
	for _, e := range []Entity{
		{Kind: "users", Owner: "victim", Name: "x"},          // another tenant
		{Kind: "certs", Owner: AdminOrg, Name: "cert-hanzo"}, // platform trust material
		{Kind: "applications", Owner: AdminOrg, Name: "hanzo-cloud"},
		{Kind: "users", Owner: "", Name: "x"}, // an unowned target
	} {
		if orgAdmin.CanEntity(Write, e, env) {
			t.Errorf("an org admin wrote %s %s/%s", e.Kind, e.Owner, e.Name)
		}
	}
	if !user.CanEntity(Read, Entity{Kind: "users", Owner: "acme", Name: "alice"}, env) {
		t.Error("a regular user cannot read its own record")
	}
	if user.CanEntity(Write, Entity{Kind: "users", Owner: "acme", Name: "alice"}, env) {
		t.Error("a regular user WROTE its own record — that is self-promotion")
	}
	if user.CanEntity(Read, Entity{Kind: "users", Owner: "acme", Name: "boss"}, env) {
		t.Error("a regular user read a colleague's record")
	}
	// The tenant registry is the ONE exception to the reserved-owner gate: an org
	// row is the TENANT'S own record, filed under the admin owner.
	if !user.CanEntity(Read, Entity{Kind: "organizations", Owner: AdminOrg, Name: "acme"}, env) {
		t.Error("a tenant cannot read its own org row")
	}
	if user.CanEntity(Write, Entity{Kind: "organizations", Owner: AdminOrg, Name: "acme"}, env) {
		t.Error("a regular user edited its own org row")
	}
	if !orgAdmin.CanEntity(Write, Entity{Kind: "organizations", Owner: AdminOrg, Name: "acme"}, env) {
		t.Error("an org admin cannot edit its own org row")
	}
	if orgAdmin.CanEntity(Read, Entity{Kind: "organizations", Owner: AdminOrg, Name: "victim"}, env) {
		t.Error("an org admin read another tenant's org row")
	}
	var nilClaims *Claims
	if nilClaims.CanEntity(Read, Entity{Kind: "users", Owner: "acme", Name: "alice"}, env) {
		t.Error("nil claims authorized a registry read")
	}
}

// BoundTo is the <org>-<app> tenant binding: app/hanzo-team acts on organization
// hanzo and on no other tenant's. A human is never bound by it, and so is never
// admitted by it.
func TestBoundToIsTheOrgNamePrefix(t *testing.T) {
	team := app(AdminOrg, "hanzo-team", "")
	if !team.BoundTo("hanzo") {
		t.Error("hanzo-team is not bound to hanzo")
	}
	for _, org := range []string{"hanzo-team", "acme", "hanzo-t", "", "hanzo-team-x"} {
		if team.BoundTo(org) {
			t.Errorf("hanzo-team was bound to %q", org)
		}
	}
	if (&Claims{Owner: "hanzo", PreferredUsername: "z"}).BoundTo("hanzo") {
		t.Error("a human was admitted by the app tenant binding")
	}
}

// The reserved set is ONE predicate, composed from the signing owners so a newly
// reserved signing owner is covered for free.
func TestReservedOrgs(t *testing.T) {
	for _, o := range []string{AdminOrg, "built-in", serviceOrg} {
		if !IsReservedOrg(o) {
			t.Errorf("%q is not reserved", o)
		}
	}
	for _, o := range []string{"acme", "", "administrator", "app-store"} {
		if IsReservedOrg(o) {
			t.Errorf("%q is reserved", o)
		}
	}
	if IsSigningOwner(serviceOrg) {
		t.Error("the service org is a signing owner")
	}
}

// principal builds a person: their own org, their name in it, and the membership
// set IAM signs home-org-first.
func person(org, name string, admin bool, orgs map[string]Role) *Principal {
	return &Principal{Org: org, User: name, Admin: admin, Orgs: orgs}
}

// MEMBERSHIP IS THE AUTHORITY ON THE TENANT REGISTRY, not the account's owner half.
// A person's account lives in ONE org while the orgs they work in are a set, so
// keying the org row on the home org alone refuses an org's own admin the org they
// administer — which is what made a second org invisible in every console.
func TestOrgRowFollowsMembershipNotTheAccountOwner(t *testing.T) {
	env := allow(nil)
	org := func(name string) Entity { return Entity{Kind: "organizations", Owner: AdminOrg, Name: name} }

	// alice's account lives in acme; she also runs team-x and merely belongs to lux.
	alice := person("acme", "alice", false, map[string]Role{"team-x": Admin, "lux": Member})

	for _, tc := range []struct {
		org        string
		read, edit bool
	}{
		{"acme", true, false},    // home org: belongs, but is not its admin
		{"team-x", true, true},   // an org she helps run
		{"lux", true, false},     // an org she merely belongs to
		{"victim", false, false}, // an org she has nothing to do with
	} {
		if got := alice.CanEntity(Read, org(tc.org), env); got != tc.read {
			t.Errorf("read %s = %v, want %v", tc.org, got, tc.read)
		}
		if got := alice.CanEntity(Write, org(tc.org), env); got != tc.edit {
			t.Errorf("write %s = %v, want %v", tc.org, got, tc.edit)
		}
	}

	// An owner membership edits too — IAM assigns `owner` to whoever creates an org,
	// so a table matching only `admin` refuses every self-serve founder their own.
	founder := person("acme", "z", false, map[string]Role{"newco": Owner})
	if !founder.CanEntity(Write, org("newco"), env) {
		t.Error("the founder of an org cannot edit it")
	}

	// Membership does not leak past the tenant registry: it admits an ORG ROW and
	// nothing else under a reserved owner, and no row of another tenant.
	for _, e := range []Entity{
		{Kind: "users", Owner: AdminOrg, Name: "root"},
		{Kind: "certs", Owner: AdminOrg, Name: "cert-hanzo"},
		{Kind: "users", Owner: "team-x", Name: "bob"},
	} {
		if alice.CanEntity(Read, e, env) || alice.CanEntity(Write, e, env) {
			t.Errorf("membership reached %s %s/%s", e.Kind, e.Owner, e.Name)
		}
	}
}

// THE CREDENTIAL MINTER READS THE KEY SET IT MANAGES. The client already trusted to
// mint, rotate and revoke a principal's credential also reads it back — strictly
// less disclosure than the mint it holds, and safe on its own because every key
// read is masked. Without the mapping the ONE key list is platform-sudo-only, so
// the surface a person calls to see their own keys has no truthful read at all.
func TestKeysMapToTheMintCapability(t *testing.T) {
	if capFor("keys") != CapKeyMint {
		t.Fatalf("capFor(\"keys\") = %+v, want CapKeyMint", capFor("keys"))
	}
	env := allow(map[string]string{"IAM_KEY_MINT_ALLOWED_APPS": "hanzo-console"})

	// The credential administrator: an admin-owned, allow-listed console serving one
	// tenant ("hanzo"). Its row owner is the reserved signing owner (the pin); the
	// org it serves is where its reads land.
	console := app(AdminOrg, "hanzo-console", "")
	console.Owner = "hanzo"

	// MINT REACHES ANOTHER TENANT. Writing a credential on another principal's behalf
	// is the whole point of the capability.
	if !console.CanEntity(Write, Entity{Kind: "keys", Owner: "acme", Name: "k"}, env) {
		t.Error("the allow-listed minter cannot mint a key in the tenant it provisions")
	}
	// READING A NAMED ROW DOES NOT. A mint capability writes a key; it does not read
	// another tenant's back. This is the cross-tenant item read the finding proved
	// live (hanzo-console GET /v1/iam/keys/lux/lux-secret-key -> 200).
	if console.CanEntity(Read, Entity{Kind: "keys", Owner: "acme", Name: "k"}, env) {
		t.Error("the minter read a NAMED key of a tenant it does not serve")
	}
	// Its OWN served tenant's named key it does read — the surface a person calls to
	// see one of their keys, masked.
	if !console.CanEntity(Read, Entity{Kind: "keys", Owner: "hanzo", Name: "k"}, env) {
		t.Error("the minter cannot read a named key of the tenant it serves")
	}
	// A COLLECTION read (no name) is admitted here; the list handler pins the tenant
	// from the same served org, so a foreign owner is refused there, not here.
	if !console.CanEntity(Read, Entity{Kind: "keys", Owner: "acme"}, env) {
		t.Error("the minter was refused a key collection at the policy — the list handler pins it")
	}
	// An empty owner is not a row: a named read with no owner is refused, and can
	// never bind another tenant's key.
	if console.CanEntity(Read, Entity{Kind: "keys", Owner: "", Name: "k"}, env) {
		t.Error("the minter read a named key with no owner")
	}

	// The owner-pin still holds either side of the tenant pin: a tenant app reusing
	// the allow-listed NAME, and an unlisted app, each hold nothing.
	spoof := app("acme", "hanzo-console", "")
	spoof.Owner = "acme"
	if spoof.CanEntity(Read, Entity{Kind: "keys", Owner: "acme", Name: "k"}, env) {
		t.Error("a tenant app reusing the allow-listed name read its own key set through the cap")
	}
	other := app(AdminOrg, "other-app", "")
	other.Owner = "hanzo"
	if other.CanEntity(Read, Entity{Kind: "keys", Owner: "hanzo", Name: "k"}, env) {
		t.Error("an app that is not allow-listed read the key set")
	}
}

// A CAPABILITY WRITES ACROSS TENANTS; ITS NAMED READ STAYS IN THE ONE IT SERVES.
// Minting a key or moving an onboarding user reaches another tenant by design — that
// is provisioning. Reading a NAMED row of another tenant does not follow from it: a
// mint capability grants writing a key, not reading another tenant's back. Proven
// live against both kinds (keys/lux/lux-secret-key and users/lux/lux-alice -> 200).
func TestCapabilityNamedReadIsPinnedToTheServedTenant(t *testing.T) {
	env := allow(map[string]string{
		"IAM_KEY_MINT_ALLOWED_APPS": "hanzo-console",
		"IAM_USER_ADMIN_APPS":       "hanzo-console",
	})
	// The console's row is admin-owned (the pin); it serves the tenant "hanzo".
	console := app(AdminOrg, "hanzo-console", "")
	console.Owner = "hanzo"

	for _, kind := range []string{"keys", "users"} {
		// The provisioning write reaches the tenant it serves for.
		if !console.CanEntity(Write, Entity{Kind: kind, Owner: "lux", Name: "x"}, env) {
			t.Errorf("%s: the console cannot provision cross-tenant, which is the capability's purpose", kind)
		}
		// The cross-tenant NAMED read is severed.
		if console.CanEntity(Read, Entity{Kind: kind, Owner: "lux", Name: "x"}, env) {
			t.Errorf("%s: the console read a NAMED row of a tenant it does not serve", kind)
		}
		// Its own served tenant's named row it reads.
		if !console.CanEntity(Read, Entity{Kind: kind, Owner: "hanzo", Name: "x"}, env) {
			t.Errorf("%s: the console cannot read a named row of the tenant it serves", kind)
		}
		// A named read with no owner binds no row and is refused — the empty target a
		// call plane computes when nothing binds the URL cannot reach another tenant.
		if console.CanEntity(Read, Entity{Kind: kind, Owner: "", Name: "x"}, env) {
			t.Errorf("%s: an empty-owner named read was admitted", kind)
		}
		// The collection read (no name) is admitted; its list handler pins the tenant.
		if !console.CanEntity(Read, Entity{Kind: kind, Owner: "hanzo"}, env) {
			t.Errorf("%s: the console was refused a collection read the list handler pins", kind)
		}
	}
}

// The capability primitives, fail-secure to the letter, and the mapping that says
// which kind needs which. An unmapped kind denies exactly as an unset allowlist
// does — that is the live behaviour for every capability a deployment leaves empty.
func TestCapabilityPrimitives(t *testing.T) {
	env := allow(map[string]string{"IAM_ORG_ADMIN_APPS": "hanzo-console, brand-console"})

	if !app(AdminOrg, "brand-console", "").Holds(CapOrgAdmin, env) {
		t.Error("a named, admin-owned app holds nothing") // the list is comma-and-space separated
	}
	if app(AdminOrg, "hanzo-consol", "").Holds(CapOrgAdmin, env) {
		t.Error("a name that merely prefixes a listed one held the capability")
	}
	if (&Principal{App: &App{Name: "hanzo-console"}}).Holds(CapOrgAdmin, env) {
		t.Error("an app with no owning org at all held a capability")
	}
	if app(AdminOrg, "hanzo-console", "").Holds(CapKeyMint, env) {
		t.Error("an unset allowlist admitted an app") // IAM_KEY_MINT_ALLOWED_APPS is absent here
	}
	if (&Principal{App: &App{Name: "hanzo", Owner: AdminOrg}}).BoundTo("hanzo") {
		t.Error("an exact-name app — no agent segment — is bound to nothing")
	}

	for kind, want := range map[string]Cap{
		"organizations": CapOrgAdmin,
		"users":         CapUserAdmin,
		"keys":          CapKeyMint,
		"certs":         {},
		"providers":     {},
		"":              {},
	} {
		if got := capFor(kind); got != want {
			t.Errorf("capFor(%q) = %+v, want %+v", kind, got, want)
		}
	}

	var nobody *Principal
	if nobody.Holds(CapOrgAdmin, env) || nobody.BoundTo("hanzo") || nobody.CanEntity(Read, Entity{}, env) {
		t.Error("a nil principal was granted something")
	}
}

// The wire and the decision cannot drift: Claims answer the registry question by
// PROJECTING onto the principal, so there is one calculus and two spellings of the
// same fact rather than two calculi.
func TestClaimsProjectOntoTheDecision(t *testing.T) {
	env := allow(map[string]string{"IAM_ORG_ADMIN_APPS": "hanzo-console"})
	for _, c := range []*Claims{
		{Owner: "acme", PreferredUsername: "alice", Orgs: []Membership{{Org: "acme", Role: Member}}},
		{Owner: "acme", PreferredUsername: "boss", IsAdmin: true, Orgs: []Membership{{Org: "acme", Role: Admin}}},
		{Owner: AdminOrg, PreferredUsername: "z", Orgs: []Membership{{Org: AdminOrg, Role: Admin}}},
		app(AdminOrg, "hanzo-console", "cert-hanzo"),
		nil,
	} {
		for _, v := range []Verb{Read, Write} {
			for _, e := range []Entity{
				{Kind: "users", Owner: "acme", Name: "alice"},
				{Kind: "organizations", Owner: AdminOrg, Name: "acme"},
				{Kind: "certs", Owner: AdminOrg, Name: "cert-hanzo"},
				{Kind: "applications", Owner: AdminOrg, Name: "hanzo-console"},
			} {
				if c.CanEntity(v, e, env) != c.Principal().CanEntity(v, e, env) {
					t.Fatalf("claims and principal disagree on %s %s %s/%s", v, e.Kind, e.Owner, e.Name)
				}
			}
		}
		if c.Holds(CapOrgAdmin, env) != c.Principal().Holds(CapOrgAdmin, env) {
			t.Fatal("claims and principal disagree on a capability")
		}
		if c.BoundTo("hanzo") != c.Principal().BoundTo("hanzo") {
			t.Fatal("claims and principal disagree on the tenant binding")
		}
	}
}

// A NAMELESS APP AUTHORIZES NOTHING. The allowlist is keyed on the application
// NAME and the self-read clause matches on it, so a name of "" turns both into a
// comparison against the empty string — and an UNSET allowlist splits to exactly
// one empty field. Before the guard, such a principal held EVERY capability off
// EVERY unset allowlist, which is a cross-tenant user write: total compromise from
// a malformed row rather than from a missing gate.
//
// The Application writer rejects an empty name today. That is one validation, in
// one repo; this is the decision refusing to depend on it.
func TestNamelessAppAuthorizesNothing(t *testing.T) {
	nameless := &Principal{App: &App{Name: "", Owner: AdminOrg}, Org: "acme"}

	for _, cap := range []Cap{CapKeyMint, CapUserAdmin, CapOrgAdmin,
		CapServiceAccountRead, CapKeyResolve, CapPublishableResolve} {
		// Unset, empty, and a list that happens to carry a blank field: all deny.
		for name, env := range map[string]Env{
			"unset": allow(nil),
			"empty": allow(map[string]string{cap.Env: ""}),
			"blank": allow(map[string]string{cap.Env: "a,,b"}),
			"comma": allow(map[string]string{cap.Env: ","}),
			"space": allow(map[string]string{cap.Env: " , "}),
		} {
			if nameless.Holds(cap, env) {
				t.Errorf("a nameless app held %s off a %s allowlist", cap.Name, name)
			}
		}
	}

	env := allow(map[string]string{
		"IAM_USER_ADMIN_APPS": "hanzo-console", "IAM_ORG_ADMIN_APPS": "hanzo-console",
	})
	for _, e := range []Entity{
		{Kind: "users", Owner: "victim", Name: "x"},
		{Kind: "users", Owner: "acme", Name: "alice"},
		{Kind: "organizations", Owner: AdminOrg, Name: "victim"},
		{Kind: "applications", Owner: AdminOrg, Name: ""},
		{Kind: "applications", Owner: "acme", Name: ""},
		{Kind: "certs", Owner: AdminOrg, Name: ""},
		{Kind: "keys", Owner: "acme", Name: ""},
		{Kind: "projects", Owner: "acme", Name: ""},
	} {
		for _, v := range []Verb{Read, Write} {
			if nameless.CanEntity(v, e, env) {
				t.Errorf("a nameless app was authorized %s on %s %s/%s", v, e.Kind, e.Owner, e.Name)
			}
		}
	}

	// A named app is unaffected: the guard rejects the malformed input and nothing
	// else. And an empty field in an OTHERWISE VALID list does not admit it either.
	console := app(AdminOrg, "hanzo-console", "")
	if !console.Holds(CapOrgAdmin, allow(map[string]string{"IAM_ORG_ADMIN_APPS": "hanzo-console,,other"})) {
		t.Error("a listed app lost its capability because the list carried a blank field")
	}
	if !console.CanEntity(Write, Entity{Kind: "organizations", Owner: AdminOrg, Name: "acme"}, env) {
		t.Error("the guard revoked a legitimate capability")
	}
	// A person is still vacuous, and still decided by the org policy.
	if !(&Principal{Org: "acme", User: "alice"}).Holds(CapKeyMint, allow(nil)) {
		t.Error("a person was refused by the app capability gate")
	}
}

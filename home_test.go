package authz

import "testing"

// THE `owner` CLAIM IS THE APPLICATION'S ORG, NOT THE USER'S.
//
// IAM's Sign stamps `Owner: app.Organization` (internal/oidc/jwt.go) for every
// authorization_code and refresh token — so `owner` follows whichever APP the person
// signed in through, not who they are. A user's own org is the first entry of the
// membership set, which store.MemberOrgRefs builds home-first from the user row.
//
// Reading `owner` as the home org therefore makes platform authority a property of
// the APPLICATION: anyone who signs into an app whose Organization is the reserved
// admin org arrives as a platform admin, whoever they are. cloud found this and
// stopped reading the claim; this leaf still read it, and gateway, tasks and cloud
// all now ask this leaf.
func TestPlatformAuthorityIsTheUserOrgNotTheAppOrg(t *testing.T) {
	// A PLAIN MEMBER of acme, signed in through an app owned by the reserved org.
	// Everything here is what IAM actually mints for that person.
	c := &Claims{
		Owner:             AdminOrg, // the APP's org — IAM put it here, the user did not
		Organization:      AdminOrg,
		PreferredUsername: "alice",
		Orgs:              []Membership{{Org: "acme", Role: Member}}, // who she actually is
	}
	c.Subject = "uuid-alice"

	if got := c.Home(); got != "acme" {
		t.Errorf("Home() = %q, want acme — the user's org, not the app's", got)
	}
	if c.Sudo() {
		t.Error("a plain member holds PLATFORM SUDO because she signed in through an admin-org app")
	}
	if org, switched := c.EffectiveOrg("victim"); switched || org != "acme" {
		t.Errorf("she masqueraded into %q (switched=%v)", org, switched)
	}
	if c.Can(Read, Path{"victim", "prod"}, nil) {
		t.Error("she may read another tenant")
	}
	if c.OrgAdmin(AdminOrg) {
		t.Error("she administers the reserved org")
	}

	// A REAL platform operator: their own membership is in the reserved org.
	op := &Claims{
		Owner:             "hanzo", // signed in through an ordinary app — irrelevant
		PreferredUsername: "z",
		Orgs:              []Membership{{Org: AdminOrg, Role: Admin}},
	}
	op.Subject = "uuid-z"
	if got := op.Home(); got != AdminOrg {
		t.Errorf("operator Home() = %q, want %s", got, AdminOrg)
	}
	if !op.Sudo() {
		t.Error("a real operator lost platform sudo because the APP they used was not the admin org")
	}
	if org, switched := op.EffectiveOrg("customer"); !switched || org != "customer" {
		t.Errorf("the operator cannot view another tenant: got %q switched=%v", org, switched)
	}
}

// A MEMBERSHIP OF THE ADMIN ORG IS NOT PLATFORM AUTHORITY.
//
// A person whose account lives in a brand org (orgs[0]) and who has been added to
// the admin org is an ordinary person of that brand org. Platform authority is
// SuperAdmin, and SuperAdmin is owning an account IN the admin org; a membership
// row there opens nothing — not sudo, not an org switch into it, not
// administration of it, not a grant under it — while every other membership
// still opens its org.
func TestAnAdminMembershipFromABrandOrgHoldsNoPlatformAuthority(t *testing.T) {
	member := &Claims{
		Owner:             AdminOrg, // signed in through an application the admin org owns
		PreferredUsername: "z",
		IsAdmin:           true, // admin of hanzo, their own org
		Orgs: []Membership{
			{Org: "hanzo", Role: Owner},
			{Org: AdminOrg, Role: Admin},
			{Org: "lux", Role: Admin},
		},
	}
	member.Subject = "uuid-hanzo-z"

	if member.Sudo() {
		t.Fatal("an admin-org membership held from a brand org is platform authority")
	}
	if org, switched := member.EffectiveOrg(AdminOrg); switched || org != "hanzo" {
		t.Errorf("the membership switched them into the admin org: %q switched=%v", org, switched)
	}
	if org, switched := member.EffectiveOrg("customer"); switched || org != "hanzo" {
		t.Errorf("they acted in a tenant they do not belong to: %q switched=%v", org, switched)
	}
	if member.OrgAdmin(AdminOrg) {
		t.Error("an admin-role membership administers the admin org")
	}
	if member.Can(Read, Path{AdminOrg}, nil) {
		t.Error("the membership grants a path under the admin org")
	}
	if payer := member.LedgerOrg(AdminOrg); payer != "hanzo" {
		t.Errorf("the ledger moved to %q", payer)
	}

	p := member.Principal()
	if p.Sudo || p.Org != "hanzo" {
		t.Errorf("projection: Sudo=%v Org=%q, want false and their own org hanzo", p.Sudo, p.Org)
	}
	if p.MemberOf(AdminOrg) || p.AdminOf(AdminOrg) {
		t.Error("the projection belongs to or administers the admin org")
	}
	if member.CanEntity(Write, Entity{Kind: "organizations", Owner: AdminOrg, Name: AdminOrg}, nil) ||
		member.CanEntity(Read, Entity{Kind: "organizations", Owner: AdminOrg, Name: AdminOrg}, nil) {
		t.Error("the membership reads or writes the admin org's own registry row")
	}

	// Their other memberships are untouched.
	if org, switched := member.EffectiveOrg("lux"); !switched || org != "lux" {
		t.Errorf("an ordinary membership stopped opening its org: %q switched=%v", org, switched)
	}
	if !member.OrgAdmin("lux") || !member.OrgAdmin("hanzo") {
		t.Error("they lost administration of their own org or of one they help run")
	}

	// A named person provisioned IN the admin org is SuperAdmin, whatever else
	// they belong to.
	op := &Claims{Owner: "hanzo", PreferredUsername: "z",
		Orgs: []Membership{{Org: AdminOrg, Role: Owner}, {Org: "hanzo", Role: Member}}}
	op.Subject = "uuid-admin-z"
	if !op.Sudo() {
		t.Fatal("a person whose own org is the admin org lost platform authority")
	}
	if org, switched := op.EffectiveOrg("customer"); !switched || org != "customer" {
		t.Errorf("the SuperAdmin cannot act in another tenant: %q switched=%v", org, switched)
	}
	if payer := op.LedgerOrg("customer"); payer != AdminOrg {
		t.Errorf("the SuperAdmin billed %q, want their own org", payer)
	}
	if pp := op.Principal(); !pp.Sudo || pp.Org != AdminOrg {
		t.Errorf("projection: Sudo=%v Org=%q, want true and admin", pp.Sudo, pp.Org)
	}
}

// An org admin who signs in through an application the admin org owns carries
// `owner: admin` — the application's org. The projection must not pair their
// org-admin bit with that claim, or they administer the admin org's registry row.
func TestTheProjectionIsTheSubjectsOrgNotTheApplications(t *testing.T) {
	c := &Claims{Owner: AdminOrg, PreferredUsername: "alice", IsAdmin: true,
		Orgs: []Membership{{Org: "acme", Role: Owner}}}
	c.Subject = "uuid-alice"
	p := c.Principal()
	if p.Org != "acme" {
		t.Fatalf("Org = %q, want acme", p.Org)
	}
	if p.AdminOf(AdminOrg) || c.CanEntity(Write, Entity{Kind: "organizations", Owner: AdminOrg, Name: AdminOrg}, nil) {
		t.Error("an acme admin administers the admin org through the application's owner claim")
	}
	if !c.CanEntity(Write, Entity{Kind: "organizations", Owner: AdminOrg, Name: "acme"}, nil) {
		t.Error("the acme admin cannot edit acme")
	}

	// A machine keeps the application's org as its own, and is never an org admin.
	m := &Claims{Owner: "acme", IsAdmin: true, Type: Program}
	m.Subject = "acme/acme-worker"
	if pm := m.Principal(); pm.Org != "acme" || pm.Admin || pm.Sudo {
		t.Errorf("machine projection: Org=%q Admin=%v Sudo=%v", pm.Org, pm.Admin, pm.Sudo)
	}
}

// Only a SuperAdmin reaches the admin org through the registry decision. A
// machine that lives there is not one, so it neither reads nor administers the
// admin org's own row, whatever its org-admin bit says.
func TestOnlyASuperAdminReachesTheAdminOrg(t *testing.T) {
	machine := &Principal{Org: AdminOrg, User: "svc", Admin: true}
	if machine.MemberOf(AdminOrg) || machine.AdminOf(AdminOrg) {
		t.Error("a non-SuperAdmin living in the admin org reaches it")
	}
	row := Entity{Kind: "organizations", Owner: AdminOrg, Name: AdminOrg}
	if machine.CanEntity(Read, row, nil) || machine.CanEntity(Write, row, nil) {
		t.Error("a non-SuperAdmin living in the admin org reads or writes its row")
	}
	super := &Principal{Org: AdminOrg, User: "z", Sudo: true}
	if !super.MemberOf(AdminOrg) || !super.AdminOf(AdminOrg) || !super.CanEntity(Write, row, nil) {
		t.Error("the SuperAdmin does not reach the admin org")
	}
}

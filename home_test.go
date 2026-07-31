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
	if c.PlatformSudo() {
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
	if !op.PlatformSudo() {
		t.Error("a real operator lost platform sudo because the APP they used was not the admin org")
	}
	if org, switched := op.EffectiveOrg("customer"); !switched || org != "customer" {
		t.Errorf("the operator cannot view another tenant: got %q switched=%v", org, switched)
	}
}

// PLATFORM AUTHORITY IS MEMBERSHIP OF THE RESERVED ORG, AT ANY POSITION.
//
// This is a real production token's claim shape: the operator's identity is
// ANCHORED in a brand org (orgs[0], where they bill and do ordinary work) and they
// hold the reserved org as a further membership — a deliberate grant an existing
// operator made, signed by IAM and revocable by removing the row.
//
// Reading only orgs[0] denied them. It made the reserved org unreachable for every
// operator who also does ordinary work, which is all of them, while looking
// correct — the anchor and the authority are different questions.
func TestOperatorAnchoredInABrandOrgStillHoldsPlatformAuthority(t *testing.T) {
	op := &Claims{
		Owner:             "hanzo", // the APP they signed in through
		PreferredUsername: "z",
		Orgs: []Membership{
			{Org: "hanzo", Role: Admin},  // the anchor: billing, default scope
			{Org: AdminOrg, Role: Admin}, // the grant: platform authority
			{Org: "lux", Role: Admin},
			{Org: "zoo", Role: Admin},
		},
	}
	op.Subject = "2d4d67ab-uuid"

	if got := op.Home(); got != "hanzo" {
		t.Errorf("Home() = %q — the anchor is still the brand org, not the reserved one", got)
	}
	if !op.PlatformSudo() {
		t.Fatal("an operator holding the reserved org was denied platform authority")
	}
	if org, switched := op.EffectiveOrg("customer"); !switched || org != "customer" {
		t.Errorf("the operator cannot act in another tenant: %q switched=%v", org, switched)
	}
	// The ledger still follows the ANCHOR, so an operator inspecting a customer
	// spends their own org's money, never the customer's.
	if payer := op.LedgerOrg("customer"); payer != "hanzo" {
		t.Errorf("the operator billed %q, want their own anchor org", payer)
	}

	// And a plain brand user — no reserved membership — holds nothing, whatever the
	// `owner` claim says.
	plain := &Claims{Owner: AdminOrg, PreferredUsername: "alice",
		Orgs: []Membership{{Org: "acme", Role: Member}}}
	plain.Subject = "uuid-alice"
	if plain.PlatformSudo() {
		t.Error("a plain member holds platform authority")
	}
}

package authz

import "testing"

// iamClientCredentials builds the claim set IAM's client_credentials grant ACTUALLY
// signs, field for field, from internal/oidc: Sign() stamps
//
//	Subject:   app.GetId()        // "<appOwner>/<appName>"
//	Owner:     app.Organization
//	TokenType: "access-token"     // NEVER "application"
//	Orgs:      nil                // "a machine token has no user and therefore
//	                              //  no membership set" — token.go, verbatim
//
// Every existing test in this package built its machine with TokenType:"application",
// a value no IAM code path assigns — so the machine narrowing was only ever exercised
// against a token shape that does not exist, and passed.
func iamClientCredentials(org string) *Claims {
	c := &Claims{Owner: org, TokenType: "access-token", Orgs: nil}
	c.Subject = org + "/kms-sync"
	c.Audience = []string{"kms-sync"} // audienceFor(app, "") — the client id
	return c
}

// A confidential client owned by the reserved admin org must hold NO platform
// authority. It is the case the doc comment on PlatformSudo names outright: "any
// admin-org client_credentials identity — the KMS sync app, say — could name a
// victim org and the edge would mint it, handing every backend that trusts the
// minted header a cross-tenant read."
//
// The narrowing has to bite on the token IAM signs, not on a token shape invented
// by the test.
func TestAdminOrgMachineHoldsNoPlatformAuthority(t *testing.T) {
	c := iamClientCredentials(AdminOrg)

	if !c.Machine() {
		t.Error("an IAM client_credentials token is not recognized as a machine")
	}
	if c.PlatformSudo() {
		t.Error("an admin-org machine holds platform sudo")
	}
	if org, switched := c.EffectiveOrg("victim"); switched || org != AdminOrg {
		t.Errorf("an admin-org machine masqueraded into another tenant: got %q switched=%v", org, switched)
	}
	if c.Can(Read, Path{"victim", "prod"}, nil) {
		t.Error("an admin-org machine may read another tenant")
	}
}

// A real platform operator keeps sudo. The narrowing must separate a person from a
// machine, not deny both — IAM mints every USER token with a membership set whose
// first entry is the home org (store.MemberOrgRefs), so a human in the admin org is
// distinguishable from an app there by what IAM signed.
func TestAdminOrgHumanKeepsPlatformSudo(t *testing.T) {
	c := &Claims{
		Owner:             AdminOrg,
		PreferredUsername: "z",
		Orgs:              []Membership{{Org: AdminOrg, Role: Admin}},
	}
	c.Subject = "3a1f-uuid"
	c.TokenType = "access-token"

	if c.Machine() {
		t.Fatal("a human platform operator is misread as a machine")
	}
	if !c.PlatformSudo() {
		t.Fatal("a human platform operator lost platform sudo")
	}
	if org, switched := c.EffectiveOrg("acme"); !switched || org != "acme" {
		t.Errorf("a platform operator cannot view another tenant: got %q switched=%v", org, switched)
	}
}

// A tenant's own confidential client is a machine too, and holds neither scope.
// Its authority is its capability allowlist, never an org's self-service surface.
func TestTenantMachineIsNeitherAdminScope(t *testing.T) {
	c := iamClientCredentials("acme")
	c.IsAdmin = true // IAM's ORG-role bit, present on the row the app was minted from

	if !c.Machine() {
		t.Error("a tenant's client_credentials token is not recognized as a machine")
	}
	if c.PlatformSudo() {
		t.Error("a tenant machine holds platform sudo")
	}
	if c.OrgAdmin("acme") {
		t.Error("a tenant machine administers its own org")
	}
}

// ACTING and PAYING are different questions. An operator viewing a customer's org
// reads the customer's data and spends the OPERATOR's ledger; a member who switches
// to a team org spends THAT org's. One function answering both would have to pick,
// and either pick is wrong for the other case.
func TestPayingIsNotActing(t *testing.T) {
	operator := &Claims{Owner: AdminOrg, PreferredUsername: "z",
		Orgs: []Membership{{Org: AdminOrg, Role: Admin}}}
	member := &Claims{Owner: "acme", PreferredUsername: "alice",
		Orgs: []Membership{{Org: "acme", Role: Member}, {Org: "beta", Role: Member}}}

	if org, _ := operator.EffectiveOrg("customer"); org != "customer" {
		t.Errorf("the operator acts in %q, want the viewed tenant", org)
	}
	if payer := operator.LedgerOrg("customer"); payer != AdminOrg {
		t.Errorf("the operator spends %q — a viewed tenant must not fund the visit", payer)
	}

	if org, _ := member.EffectiveOrg("beta"); org != "beta" {
		t.Errorf("the member acts in %q, want the selected org", org)
	}
	if payer := member.LedgerOrg("beta"); payer != "beta" {
		t.Errorf("the member spends %q, want the org acted in", payer)
	}
	// A selection outside the membership set funds nothing but the caller's own org.
	if payer := member.LedgerOrg("victim"); payer != "acme" {
		t.Errorf("an ungranted selection billed %q", payer)
	}
}

// A machine cannot move the ledger. It reads as a machine, so PlatformSudo is
// false, so LedgerOrg takes the ordinary branch and EffectiveOrg has already
// refused the selection — the two compose to "your own org pays" with no extra rule.
func TestMachineCannotMoveTheLedger(t *testing.T) {
	m := iamClientCredentials(AdminOrg)
	if payer := m.LedgerOrg("victim"); payer != AdminOrg {
		t.Errorf("an admin-org machine billed %q", payer)
	}
}

// Location stops at the first absent segment, so a project under no workspace can
// never print as a workspace of the same name.
func TestLocationStopsAtTheFirstGap(t *testing.T) {
	base := func() *Claims {
		return &Claims{Owner: "acme", PreferredUsername: "alice",
			Orgs: []Membership{{Org: "acme", Role: Member}}}
	}
	for _, c := range []struct {
		name      string
		workspace string
		project   string
		want      string
	}{
		{"org only", "", "", "acme"},
		{"workspace", "prod", "", "acme/prod"},
		{"full", "prod", "web", "acme/prod/web"},
		{"project with no workspace stops at the org", "", "web", "acme"},
		{"a non-injective workspace ends the path", "prod ", "web", "acme"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := base()
			cl.Workspace, cl.Project = c.workspace, c.project
			if got := cl.Location("").String(); got != c.want {
				t.Errorf("Location = %q, want %q", got, c.want)
			}
		})
	}
}

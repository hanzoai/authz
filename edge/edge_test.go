package edge_test

import (
	"net/http"
	"testing"

	"github.com/hanzoai/authz"
	"github.com/hanzoai/authz/edge"
	"github.com/zap-proto/zip"
)

// req builds a zip request context — the surface the fleet actually serves on, so
// the edge is tested through the same type it runs on rather than an adapter.
func req(t *testing.T) *zip.Ctx {
	t.Helper()
	return zip.New(zip.Config{AppName: "edgetest"}).TestCtx(http.MethodGet, "/v1/anything")
}

// hdr reads a REQUEST header the edge minted. The edge rewrites the request the
// next tier reads, not the response.
func hdr(c *zip.Ctx, name string) string {
	return string(c.Fiber().Request().Header.Peek(name))
}

// claim sets a header a CLIENT supplied, which is what Strip must delete.
func claim(c *zip.Ctx, name, v string) {
	c.Fiber().Request().Header.Set(name, v)
}

// THE ESCALATION. Claims.IsAdmin is IAM's ORG-role bit; the platform-authority
// header must never be minted from it. Every org owner carried IsAdmin, so minting
// X-User-IsAdmin from it made every org owner a platform admin — cross-org reads
// and the money gates.
func TestOrgOwnerIsNotAPlatformAdmin(t *testing.T) {
	owner := &authz.Claims{
		Owner:             "acme",
		PreferredUsername: "founder",
		IsAdmin:           true, // the ORG-role bit, not platform authority
		Orgs:              []authz.Membership{{Org: "acme", Role: authz.Owner}},
	}
	r := req(t)
	edge.Inject(r, owner, "", nil)

	if got := hdr(r, authz.HeaderUserAdmin); got != "" {
		t.Errorf("an org owner was minted PLATFORM authority %s=%q", authz.HeaderUserAdmin, got)
	}
	if got := hdr(r, authz.HeaderUserOrgAdmin); got != "true" {
		t.Errorf("an org owner was NOT minted %s (got %q) — the self-service surface refuses its own founder", authz.HeaderUserOrgAdmin, got)
	}
	if got := hdr(r, authz.HeaderOrg); got != "acme" {
		t.Errorf("%s = %q, want acme", authz.HeaderOrg, got)
	}
	if got := hdr(r, authz.HeaderUserOwner); got != "acme" {
		t.Errorf("%s = %q, want acme", authz.HeaderUserOwner, got)
	}
}

// An admin-org MACHINE gets neither header: not the platform one (PlatformSudo
// narrows sudo to a human, so the KMS sync identity cannot name a victim org), and
// not the org-admin one (a client_credentials app is issued for a purpose, not
// handed an org's self-service surface).
func TestAdminOrgMachineGetsNeitherAdminHeader(t *testing.T) {
	// IAM's client_credentials shape, verbatim: tokenType "access-token" and NO
	// membership set. The fixture used to carry both an "application" tokenType IAM
	// never mints and a membership set a machine token never has, so it asserted the
	// refusal against a token that cannot exist.
	machine := &authz.Claims{
		Owner:             authz.AdminOrg,
		PreferredUsername: "admin-platform-kms",
		IsAdmin:           true,
		TokenType:         "access-token",
	}
	r := req(t)
	edge.Inject(r, machine, "victim", nil)

	if got := hdr(r, authz.HeaderUserAdmin); got != "" {
		t.Errorf("an admin-org machine was minted %s=%q", authz.HeaderUserAdmin, got)
	}
	if got := hdr(r, authz.HeaderUserOrgAdmin); got != "" {
		t.Errorf("an admin-org machine was minted %s=%q", authz.HeaderUserOrgAdmin, got)
	}
	if got := hdr(r, authz.HeaderOrg); got != authz.AdminOrg {
		t.Errorf("a machine masqueraded into %q", got)
	}
}

// A HUMAN platform operator does carry sudo, and carries it into another tenant
// without acquiring that tenant's self-service authority.
func TestPlatformOperatorActsInAnotherTenantWithoutOrgAdmin(t *testing.T) {
	// A user token always carries its home org first (store.MemberOrgRefs), so a real
	// operator is distinguishable from an app in the same org by what IAM signed.
	op := &authz.Claims{
		Owner:             authz.AdminOrg,
		PreferredUsername: "z",
		IsAdmin:           true,
		Orgs:              []authz.Membership{{Org: authz.AdminOrg, Role: authz.Admin}},
	}
	r := req(t)
	edge.Inject(r, op, "victim", nil)

	if got := hdr(r, authz.HeaderUserAdmin); got != "true" {
		t.Errorf("the platform operator lost %s", authz.HeaderUserAdmin)
	}
	if got := hdr(r, authz.HeaderOrg); got != "victim" {
		t.Errorf("%s = %q, want the masqueraded org", authz.HeaderOrg, got)
	}
	if got := hdr(r, authz.HeaderUserOrgAdmin); got != "" {
		t.Errorf("the operator acquired the viewed tenant's %s", authz.HeaderUserOrgAdmin)
	}
}

// Strip deletes every header the edge mints and every authz.Retired name, and hands back
// the CLAIMED org as an input. A forged authority header never survives ingress.
func TestStripRemovesEveryMintedAndRetiredHeader(t *testing.T) {
	r := req(t)
	for _, h := range append(append([]string{}, authz.Headers...), authz.Retired...) {
		claim(r, h, "forged")
	}
	claim(r, authz.HeaderOrg, "claimed")
	claim(r, "X-Unrelated", "kept")

	if got := edge.Strip(r); got != "claimed" {
		t.Errorf("Strip returned %q, want the claimed org", got)
	}
	for _, h := range authz.Headers {
		if got := hdr(r, h); got != "" {
			t.Errorf("minted header %s survived ingress with %q", h, got)
		}
	}
	for _, h := range authz.Retired {
		if got := hdr(r, h); got != "" {
			t.Errorf("authz.Retired header %s survived ingress with %q", h, got)
		}
	}
	if got := hdr(r, "X-Unrelated"); got != "kept" {
		t.Error("Strip deleted a header it does not own")
	}
}

// Named individually, because these three are the ones a forger reaches for: the
// platform bit, and the two location narrowings IAM mints no claim for.
func TestForgedAuthorityAndScopeHeadersNeverSurvive(t *testing.T) {
	r := req(t)
	claim(r, authz.HeaderUserAdmin, "true")
	claim(r, authz.HeaderWorkspace, "victim-workspace")
	claim(r, authz.HeaderProject, "victim-project")
	claim(r, authz.HeaderScope, "victim/prod/web")
	claim(r, authz.HeaderScopeRole, "owner")
	edge.Strip(r)

	// An ordinary member, re-minted from verified claims, gets none of them back.
	edge.Inject(r, &authz.Claims{Owner: "acme", PreferredUsername: "u", Orgs: []authz.Membership{{Org: "acme", Role: authz.Member}}}, "", nil)
	for _, h := range []string{authz.HeaderUserAdmin, authz.HeaderWorkspace, authz.HeaderProject, authz.HeaderScope, authz.HeaderScopeRole} {
		if got := hdr(r, h); got != "" {
			t.Errorf("forged %s came back as %q", h, got)
		}
	}
}

// A non-injective claimed org grants nothing: "acme " and "acme" are two strings a
// trim would fold into one tenant.
func TestStripRefusesNonInjectiveClaimedOrg(t *testing.T) {
	r := req(t)
	claim(r, authz.HeaderOrg, "acme ")
	if got := edge.Strip(r); got != "" {
		t.Errorf("Strip returned %q for a non-injective org, want empty", got)
	}
}

// The resolved scope is minted only when it belongs to THIS subject: an edge
// forwarding a grant resolved for someone else is the same class of bug one tier
// deeper.
func TestInjectMintsOnlyTheSubjectOwnResolvedScope(t *testing.T) {
	c := &authz.Claims{Owner: "acme", PreferredUsername: "z", Orgs: []authz.Membership{{Org: "acme", Role: authz.Member}}}
	c.Subject = "acme/z"
	mine := &authz.Grant{Subject: "acme/z", Scope: authz.Path{"acme", "prod", "web"}, Role: authz.Member}
	theirs := &authz.Grant{Subject: "acme/other", Scope: authz.Path{"acme", "prod", "web"}, Role: authz.Owner}

	r := req(t)
	edge.Inject(r, c, "", mine)
	if got := hdr(r, authz.HeaderScope); got != "acme/prod/web" {
		t.Errorf("%s = %q, want the resolved scope", authz.HeaderScope, got)
	}
	if got := hdr(r, authz.HeaderScopeRole); got != string(authz.Member) {
		t.Errorf("%s = %q, want member", authz.HeaderScopeRole, got)
	}

	r = req(t)
	edge.Inject(r, c, "", theirs)
	if got := hdr(r, authz.HeaderScope); got != "" {
		t.Errorf("another subject's resolved scope was minted: %q", got)
	}
}

// EffectiveOrg fails closed to home: a selected org outside the signed membership
// set is not granted.
func TestEffectiveOrgFailsClosedToHome(t *testing.T) {
	c := &authz.Claims{Owner: "acme", Orgs: []authz.Membership{{Org: "acme", Role: authz.Owner}, {Org: "second", Role: authz.Member}}}
	for _, tc := range []struct {
		selected, want string
		switched       bool
	}{
		{"", "acme", false},
		{"acme", "acme", false},
		{"second", "second", true},
		{"victim", "acme", false},
		{"second ", "acme", false}, // non-injective: refused, not trimmed into "second"
	} {
		got, switched := c.EffectiveOrg(tc.selected)
		if got != tc.want || switched != tc.switched {
			t.Errorf("EffectiveOrg(%q) = (%q, %v), want (%q, %v)", tc.selected, got, switched, tc.want, tc.switched)
		}
	}
}

// The sub-scope headers are minted from the signed claims, and only as far as the
// location is whole. A project with no workspace above it mints no project header:
// the two would print as one path and collide with a workspace of that name.
func TestSubScopeHeadersFollowTheLocation(t *testing.T) {
	for _, c := range []struct {
		name          string
		workspace     string
		project       string
		wantWorkspace string
		wantProject   string
	}{
		{"neither", "", "", "", ""},
		{"workspace only", "prod", "", "prod", ""},
		{"both", "prod", "web", "prod", "web"},
		{"project with no workspace mints neither", "", "web", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := &authz.Claims{
				Owner: "acme", PreferredUsername: "alice",
				Workspace: c.workspace, Project: c.project,
				Orgs: []authz.Membership{{Org: "acme", Role: authz.Member}},
			}
			r := req(t)
			edge.Inject(r, cl, "", nil)

			if got := hdr(r, authz.HeaderWorkspace); got != c.wantWorkspace {
				t.Errorf("%s = %q, want %q", authz.HeaderWorkspace, got, c.wantWorkspace)
			}
			if got := hdr(r, authz.HeaderProject); got != c.wantProject {
				t.Errorf("%s = %q, want %q", authz.HeaderProject, got, c.wantProject)
			}
		})
	}
}

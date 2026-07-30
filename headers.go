// The header contract: the decision, in transport.
//
// Whoever holds the EDGE role strips every identity header on ingress and re-mints
// it from verified claims. Everything behind reads them and forwards them
// unchanged. A consumer that writes one is a second minter (HIP-0519).

package authz

// The identity headers, named once by the party that mints their values.
//
// These are STRINGS, so naming them costs a consumer nothing: reading a header is
// the whole of what a service behind the edge does with identity. Minting them is
// the edge's job and lives in authz/edge, which links a transport — this package
// deliberately does not.
const (
	HeaderOrg            = "X-Org-Id"
	HeaderWorkspace      = "X-Workspace-Id"
	HeaderProject        = "X-Project-Id"
	HeaderUser           = "X-User-Id"
	HeaderUserName       = "X-User-Name"
	HeaderUserEmail      = "X-User-Email"
	HeaderUserOwner      = "X-User-Owner"
	HeaderUserAdmin      = "X-User-IsAdmin"
	HeaderUserOrgAdmin   = "X-User-IsOrgAdmin"
	HeaderBillingAccount = "X-Billing-Account-Id"
	HeaderRequestID      = "X-Request-Id"

	// HeaderScope carries the resolved LOCATION a request acts at, printed as a path
	// (acme/prod/web), and HeaderScopeRole the role held there. This pair is why a
	// token stays constant-size: the edge resolves the requested scope against the
	// grant set ONCE, mints the outcome here, and no decision behind the edge performs
	// I/O. The grant SET stays in IAM, which signs it; the resolved DECISION travels.
	HeaderScope     = "X-Scope"
	HeaderScopeRole = "X-Scope-Role"
)

// Headers is every header the edge mints, and therefore every header it must
// strip. A header that is minted but not stripped is forgeable; the two lists
// being one list is what makes that impossible.
var Headers = []string{
	HeaderOrg, HeaderWorkspace, HeaderProject,
	HeaderScope, HeaderScopeRole,
	HeaderUser, HeaderUserName, HeaderUserEmail, HeaderUserOwner,
	HeaderUserAdmin, HeaderUserOrgAdmin,
	HeaderBillingAccount,
}

// retired are header names an older edge minted. They are stripped and never
// emitted: a client that sends one must not have it believed by a consumer that
// still reads it.
// Retired is exported because the edge must strip these too: a name an older edge
// minted is a name some consumer may still read, so a client that sends one must
// not have it believed.
var Retired = []string{
	"X-User-IsGlobalAdmin", "X-Roles", "X-User-Role", "X-User-Roles",
	"X-User-Permissions", "X-Tenant-Id", "X-Phone-Number", "X-Org",
}

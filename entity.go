// IAM's identity registry: who may act on a row of identity material.
//
// This is a DIFFERENT question from the grant model in grant.go, and stays a
// different predicate. Grants authorize a LOCATION — org/workspace/project and
// below. The registry addresses IAM's own rows by (owner, name) and adds three
// things a location cannot express: the reserved-owner gate that keeps signing
// material out of a tenant's reach, the capability allowlist a confidential client
// is limited to, and the self-read clauses by which a relying party bootstraps
// itself. Two questions, two predicates, no overlap.
//
// Lifted from iam/internal/authz, which had to live in IAM because its Principal
// was resolved there. The DECISION is pure and belongs beside the grant model;
// what needs a store — resolving the principal, loading the user record — stays
// in IAM.

package authz

import "strings"

// Entity addresses one row in IAM's identity registry: its Kind (the plural
// entity noun — users, certs, applications, organizations, projects) and the
// (Owner, Name) pair identifying it.
type Entity struct {
	Kind  string
	Owner string
	Name  string
}

// Cap is one capability a confidential client may hold: a Name for diagnostics
// and the Env variable holding its comma-separated allowlist of application names.
//
// A Cap is the ONLY thing an app principal's authority is made of — an app is
// never a platform admin and never an org admin — so a leaked client credential
// grants exactly the capabilities its NAME was allowlisted for and nothing more.
type Cap struct {
	Name string
	Env  string
}

// The capability set, matching the live allowlists byte for byte (universe
// infra/k8s/operator/crs/iam.yaml). Every one is fail-secure: an unset or empty
// allowlist denies EVERY app.
var (
	// CapKeyMint gates minting, rotating, or revoking a credential on another
	// principal's behalf — the service-account administration boundary, since a
	// minted key is an org-billing credential.
	CapKeyMint = Cap{Name: "key-mint", Env: "IAM_KEY_MINT_ALLOWED_APPS"}

	// CapUserAdmin gates cross-user account mutation (owner, isAdmin, email, type,
	// credentials) — cloud moves an onboarding user into the org it just created
	// through this.
	CapUserAdmin = Cap{Name: "user", Env: "IAM_USER_ADMIN_APPS"}

	// CapOrgAdmin gates organization create/read/update/delete. Unlike the
	// signing-material capabilities this one is populated in every environment: the
	// brand consoles legitimately create customer orgs during onboarding.
	CapOrgAdmin = Cap{Name: "organization", Env: "IAM_ORG_ADMIN_APPS"}

	// CapServiceAccountRead gates LISTING an org's service accounts — names and
	// metadata only, never secrets. It is the read-only counterpart to CapKeyMint (a
	// read cap can never mint, rotate, or delete a credential) and is additionally
	// tenant-bound by BoundTo.
	CapServiceAccountRead = Cap{Name: "service-account-read", Env: "IAM_SA_LIST_ALLOWED_APPS"}

	// CapKeyResolve gates resolving an opaque SECRET API key (hk-/sk-) to its owning
	// principal. It is a CREDENTIAL-DISCLOSURE boundary: the caller presents a secret
	// key and learns WHO it authenticates, so it must never be an arbitrary
	// authenticated caller. A public pk- is NOT resolved here — it is write-only, and
	// its own narrower CapPublishableResolve turns it into an org, never a principal.
	// The intended sole holder is cloud's identity boundary, which turns a keyed
	// request into the same principal a JWT yields. A human holds it vacuously, so
	// the handler also requires an app principal to keep this a service-only door.
	CapKeyResolve = Cap{Name: "key-resolve", Env: "IAM_KEY_RESOLVE_APPS"}

	// CapPublishableResolve gates resolving a WRITE-ONLY publishable pk- to just the
	// ORG that holds it, for cloud's ingest boundary. It is strictly NARROWER than
	// CapKeyResolve and deliberately a separate authority: this door discloses only
	// an org (a pk- is public, shipped in client JS), NEVER a principal, so a client
	// granted org-resolve must never thereby be able to disclose WHO a secret key
	// authenticates.
	CapPublishableResolve = Cap{Name: "publishable-resolve", Env: "IAM_PUBLISHABLE_RESOLVE_APPS"}
)

// Env resolves a capability allowlist by variable name. os.Getenv satisfies it in
// a server; a map literal satisfies it in a test.
//
// The allowlist is per-environment DATA, so the decision takes the lookup as an
// INPUT and never reads the process environment itself — that is what keeps this
// leaf free of config. A nil Env denies every capability.
type Env func(name string) string

// Holds reports whether these claims hold capability cap.
//
// A non-app principal holds every capability vacuously: this gate concerns
// confidential clients ONLY, and a human's authority is decided by CanEntity.
// Conflating the two would either lock every human out or hand every app a
// human's scope. Nil claims hold nothing.
//
// Fail-secure: an app whose allowlist is unset, empty, or does not name it holds
// nothing.
//
// The key is the application NAME, not its (owner, name) row. That alone would let
// ANY owner's app claim a listed name, so Holds ALSO pins the app's OWNING org to a
// reserved platform signing owner: the name is thereby reserved to the platform's
// admin-owned app, and a tenant that registers <theirOrg>/hanzo-console — same
// name, its own owner — inherits none of its grants. The pin is what ENFORCES that
// reservation; the name match alone was the escalation.
func (c *Claims) Holds(cap Cap, env Env) bool {
	if c == nil {
		return false
	}
	if c.App == nil {
		return true // not an app; the org policy decides
	}
	if !IsSigningOwner(c.App.Owner) {
		return false
	}
	if cap.Env == "" || env == nil {
		return false
	}
	for _, item := range strings.Split(env(cap.Env), ",") {
		if strings.TrimSpace(item) == c.App.Name {
			return true
		}
	}
	return false
}

// BoundTo reports whether an app principal is bound to org by the <org>-<app>
// naming convention — app/hanzo-team may act on organization=hanzo and on no
// other tenant's. The org is derived from the (allowlist-reserved) application
// NAME, so the binding holds regardless of the app row's owner, and it is the same
// prefix rule the service-account names it reads obey. A human is never bound by
// it, and so is never admitted by it.
func (c *Claims) BoundTo(org string) bool {
	if c == nil || c.App == nil || org == "" {
		return false
	}
	prefix := org + "-"
	return len(c.App.Name) > len(prefix) && strings.HasPrefix(c.App.Name, prefix)
}

// capFor maps an entity kind to the capability a confidential client needs to act
// on it. A kind with NO mapping grants an app nothing: unmapped denies exactly as
// an unset allowlist does, which is the live behaviour for every capability a
// deployment leaves empty — certs, providers, tokens, syncers and webhooks are all
// deny-all by design, because no client credential should ever reach signing
// material. Only the two kinds a live confidential client touches are mapped: the
// brand consoles create customer orgs, and cloud moves the onboarding user into
// the org it just created.
func capFor(kind string) Cap {
	switch kind {
	case "organizations":
		return CapOrgAdmin
	case "users":
		return CapUserAdmin
	}
	return Cap{}
}

// CanEntity reports whether these claims may v on the addressed registry row.
//
// Three scopes, never conflated (conflation is privilege escalation):
//
//   - PLATFORM SUDO — the home org is the reserved admin org. The only cross-tenant
//     scope, and the only one that may write a platform-owned row: the signing-cert
//     poisoning gate, admin-scoped application and provider registration, every
//     reserved surface.
//   - ORG ADMIN — IsAdmin, scoped to its OWN org. Manages every row its org owns;
//     never another org's, never a platform-owned one.
//   - REGULAR USER — self-service only: reading its own user record. The users kind
//     serves reads as GET and writes as POST, so gating the self clause to a read
//     keeps a regular user from writing its own record, which would otherwise let it
//     carry isAdmin and self-promote.
//
// A confidential client sits outside all three: its authority is its capability
// allowlist plus the self-read clauses, and nothing else.
func (c *Claims) CanEntity(v Verb, e Entity, env Env) bool {
	if c == nil {
		return false
	}
	if c.PlatformSudo() {
		return true
	}
	if c.App != nil && v == Read {
		// Its OWN application row, and no other. Reading its own registration is the
		// ordinary bootstrap of an OIDC relying party — how a client discovers its cert,
		// redirect URIs and enabled methods — and reveals nothing the holder of that
		// client's credential does not already have.
		//
		// Narrow by construction, four ways at once: only an app principal, only a read
		// (never a write to its own row, which would let a client widen its own redirect
		// URIs or grants), only the applications kind, and only the exact (Owner, Name)
		// pair the request authenticated as. Both halves must match, so this is
		// self-read and not "apps may read applications": a sibling in the same org
		// differs in name and stays refused, and admin/<app> vs <tenant>/<app> — the
		// same name under a different owner — differs in owner, so neither direction of
		// that collision is admitted.
		if e.Kind == "applications" && e.Owner != "" && e.Owner == c.App.Owner && e.Name == c.App.Name {
			return true
		}
		// ...and the ONE signing cert that row references. A relying party cannot
		// bootstrap without it: it reads its application, then the cert the application
		// names, then initialises from that certificate — so granting only the
		// application fixes one line and fails identically on the next.
		//
		// Scoped to the cert its OWN application names, never "apps may read certs": the
		// name must equal the cert on the authenticated row, so an app cannot walk to
		// another brand's signing cert. The owner half varies by CALLER — some send
		// <servedOrg>/<name>, some hardcode the admin owner, a bare ?id= carries no owner
		// at all — so all three shapes are admitted and the NAME is the whole gate. The
		// read is masked anyway: what crosses the wire is the PUBLIC certificate this
		// client already has to trust to verify our tokens.
		if e.Kind == "certs" && c.App.Cert != "" && e.Name == c.App.Cert &&
			(e.Owner == "" || e.Owner == c.App.Owner || e.Owner == c.Owner) {
			return true
		}
		// An org's OWN PaaS machine identity may READ that org's projects, and nothing
		// else. This is how cloud's platform resolves a tenant's projects from the
		// canonical store here instead of a second embedded database — the split-brain
		// where a project created in IAM was invisible to the PaaS and vice versa.
		//
		// Narrow the same four ways: only a read; only the projects kind; only the
		// caller's OWN org, so one tenant's identity can never walk another's list; and
		// only the identity the "<org>-platform-kms" contract names — the same string
		// cloud recognises in order to DENY that principal platform sudo. The contract
		// is the grant, stated once; no env allowlist to drift.
		if e.Kind == "projects" && e.Owner != "" && e.Owner == c.Owner &&
			c.App.Name == c.Owner+"-platform-kms" {
			return true
		}
	}
	if IsReservedOrg(e.Owner) {
		// The ONE exception to the reserved-owner gate is the tenant registry: every
		// organization row is filed under the admin owner, but an org row is the
		// TENANT'S own record, not platform trust material — a tenant reads its own org,
		// its admin edits it, and an org-admin-capable confidential client manages orgs
		// during onboarding. Certs, applications, providers and users under a reserved
		// owner stay platform-sudo-only.
		if e.Kind != "organizations" {
			return false
		}
		if c.App != nil {
			return c.Holds(CapOrgAdmin, env)
		}
		return e.Name == c.Owner && (v == Read || c.IsAdmin)
	}
	// A confidential client's authority is its capability allowlist and nothing else
	// — never platform sudo, never org admin; an unmapped kind or unset allowlist
	// denies.
	if c.App != nil {
		return c.Holds(capFor(e.Kind), env)
	}
	if e.Owner == "" || e.Owner != c.Owner {
		return false
	}
	if c.IsAdmin {
		return true
	}
	return v == Read && e.Kind == "users" && e.Name != "" && e.Name == c.Username()
}

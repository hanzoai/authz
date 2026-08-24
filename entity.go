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
// The DECISION is here. What needs a store — loading the user record, resolving a
// key to its owner, reading the membership rows — stays in IAM, which then states
// the outcome as a Principal and asks this.

package authz

import "strings"

// Entity addresses one row in IAM's identity registry: its Kind (the plural
// entity noun — users, certs, applications, organizations, projects, keys) and the
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
	// minted key is an org-billing credential. Minting reaches across tenants; the
	// read it also grants does not. It lists the key set it administers WITHIN THE
	// TENANT THE APP SERVES — the list handler pins that tenant — but a NAMED key of
	// another tenant is not readable through it: writing a credential into a tenant
	// is not licence to read that tenant's rows back. Every key read is masked.
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

// capFor maps an entity kind to the capability a confidential client needs to act
// on it. A kind with NO mapping grants an app nothing: unmapped denies exactly as
// an unset allowlist does, which is the live behaviour for every capability a
// deployment leaves empty — certs, providers, tokens, syncers and webhooks are all
// deny-all by design, because no client credential should ever reach signing
// material. Only the kinds a live confidential client touches are mapped: the brand
// consoles create customer orgs, cloud moves the onboarding user into the org it
// just created, and the credential administrator lists the key set it mints within
// the tenant it serves.
func capFor(kind string) Cap {
	switch kind {
	case "organizations":
		return CapOrgAdmin
	case "users":
		return CapUserAdmin
	case "keys":
		return CapKeyMint
	}
	return Cap{}
}

// Principal is WHO acts, reduced to exactly what the registry decision reads. It
// is a VALUE, not a token and not a row: IAM resolves it from its store, a service
// behind the edge projects one from verified Claims, and both then ask the same
// predicate. Resolving a principal and deciding what it may do are different jobs,
// and this type is the line between them.
type Principal struct {
	// Org is the principal's OWN organization — its tenancy anchor. For a person it
	// is the org of the account, resolved from the user record rather than from
	// whichever application minted the token. For a confidential client it is the org
	// the application SERVES, which is not the org that owns the application row.
	Org string

	// User is the principal's name within Org, and is empty for a machine. It keys
	// the one self-service clause: a regular user reads its own record.
	User string

	// Admin is the ORG-level role bit, scoped to Org and never platform authority.
	Admin bool

	// Sudo is platform authority: the only cross-tenant scope, and the only scope
	// that may write a platform-owned row.
	//
	// It is an input rather than something derived here, because WHO is an operator
	// is a resolution question with more than one honest answer — IAM reads a live
	// user record in the reserved org, a service behind the edge reads the signed
	// membership set — while WHAT an operator may do is this one decision. Deriving
	// it here would force one resolution on every caller and silently change the
	// other's boundary.
	Sudo bool

	// App is the confidential client the request authenticated as, or nil for a
	// person. An app principal is never Sudo and never Admin: its whole authority is
	// its capability allowlist plus the self-read clauses, so a leaked client
	// credential can neither read another tenant nor touch signing material.
	App *App

	// Orgs is every org the principal may act in besides — or including — its home
	// org, and the role held there. Membership is the authority on the tenant
	// registry: a person's account lives in one org while the orgs they work in are a
	// set, so keying that clause on Org alone refuses an org's own admin the org they
	// administer. Empty for an app principal, whose scope is its served tenant.
	Orgs map[string]Role
}

// memberOf reports whether p may act in org through its home org or a membership.
// It is the ONE membership question the decision asks, so no clause re-derives the
// set. Presence is the test, not the role: belonging is what a read needs.
func (p *Principal) memberOf(org string) bool {
	if p == nil || org == "" {
		return false
	}
	if org == p.Org {
		return true
	}
	_, ok := p.Orgs[org]
	return ok
}

// adminOf reports whether p may CHANGE org — its own org as an org admin, or an
// org it holds an owner/admin membership in. A plain member never qualifies:
// belonging to an org is permission to see it, not to edit it. Role.Admits folds
// owner into admin, so the founder of a self-serve org is not refused their own.
func (p *Principal) adminOf(org string) bool {
	if p == nil || org == "" {
		return false
	}
	if org == p.Org && p.Admin {
		return true
	}
	return p.Orgs[org].Admits(Write)
}

// Holds reports whether p holds capability cap.
//
// A non-app principal holds every capability vacuously: this gate concerns
// confidential clients ONLY, and a person's authority is decided by CanEntity.
// Conflating the two would either lock every person out or hand every app a
// person's scope. A nil principal holds nothing.
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
func (p *Principal) Holds(cap Cap, env Env) bool {
	if p == nil {
		return false
	}
	if p.App == nil {
		return true // not an app; the org policy decides
	}
	if !p.App.named() {
		return false
	}
	if !IsSigningOwner(p.App.Owner) {
		return false
	}
	if cap.Env == "" || env == nil {
		return false
	}
	for _, item := range strings.Split(env(cap.Env), ",") {
		// An EMPTY entry names no app. Splitting "" yields one empty field and
		// splitting "a,,b" yields another, so without this an app whose name compared
		// equal to "" held every capability off an UNSET allowlist — the failure
		// direction this gate exists to make impossible.
		if item = strings.TrimSpace(item); item != "" && item == p.App.Name {
			return true
		}
	}
	return false
}

// named reports whether the app row carries the NAME its authority is keyed on.
//
// A nameless App is a MALFORMED principal, not a person and not a client, and it
// authorizes nothing: the capability allowlist is keyed on the name and the
// self-read clause matches on it, so a name of "" turns both into a comparison
// against the empty string — which an unset allowlist and an unnamed target both
// satisfy. Refusing it here is what makes "fail-secure" true of the decision rather
// than true of whoever last validated an Application row.
func (a *App) named() bool { return a != nil && a.Name != "" }

// BoundTo reports whether an app principal is bound to org by the <org>-<app>
// naming convention — app/hanzo-team may act on organization=hanzo and on no
// other tenant's. The org is derived from the (allowlist-reserved) application
// NAME, so the binding holds regardless of the app row's owner, and it is the same
// prefix rule the service-account names it reads obey. A person is never bound by
// it, and so is never admitted by it.
func (p *Principal) BoundTo(org string) bool {
	if p == nil || p.App == nil || org == "" {
		return false
	}
	prefix := org + "-"
	return len(p.App.Name) > len(prefix) && strings.HasPrefix(p.App.Name, prefix)
}

// CanEntity reports whether p may v on the addressed registry row. The order IS
// the policy.
//
// Three scopes, never conflated (conflation is privilege escalation):
//
//   - PLATFORM SUDO — the only cross-tenant scope, and the only one that may write
//     a platform-owned row: the signing-cert poisoning gate, admin-scoped
//     application and provider registration, every reserved surface.
//   - ORG ADMIN — scoped to its OWN org. Manages every row its org owns; never
//     another org's, never a platform-owned one.
//   - REGULAR USER — self-service only: reading its own user record. The users kind
//     serves reads as GET and writes as POST, so gating the self clause to a read
//     keeps a regular user from writing its own record, which would otherwise let it
//     carry isAdmin and self-promote. READ is the whole condition, so a HEAD of one's
//     own row is admitted with the GET: the two disclose the same row and the second
//     discloses less of it, and a probe that is refused where the fetch succeeds is
//     an inconsistency a client trips over rather than a boundary.
//
// A confidential client sits outside all three: its authority is its capability
// allowlist plus the self-read clauses, and nothing else.
func (p *Principal) CanEntity(v Verb, e Entity, env Env) bool {
	if p == nil {
		return false
	}
	if p.Sudo {
		return true
	}
	if p.App.named() && v == Read {
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
		if e.Kind == "applications" && e.Owner != "" && e.Owner == p.App.Owner && e.Name == p.App.Name {
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
		if e.Kind == "certs" && p.App.Cert != "" && e.Name == p.App.Cert &&
			(e.Owner == "" || e.Owner == p.App.Owner || e.Owner == p.Org) {
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
		if e.Kind == "projects" && e.Owner != "" && e.Owner == p.Org &&
			p.App.Name == p.Org+"-platform-kms" {
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
		if p.App != nil {
			return p.Holds(CapOrgAdmin, env)
		}
		// A person reads any org they BELONG to, and edits the ones they help run.
		// Membership is the authority here, not the account's owner half: a person's
		// account lives in one tenant while the orgs they work in are a set, so keying
		// this on the home org alone refused an org's own admin the org they administer
		// — which is what made a second org invisible in every console.
		if v == Read {
			return p.memberOf(e.Name)
		}
		return p.adminOf(e.Name)
	}
	// A confidential client's authority is its capability allowlist and nothing else
	// — never platform sudo, never org admin; an unmapped kind or unset allowlist
	// denies.
	//
	// A capability is a WRITE authority that reaches across tenants — minting a key
	// on another principal's behalf, moving an onboarding user into the org just
	// created for it. It does NOT grant reading a NAMED row of another tenant: a mint
	// capability writes a key, it does not read another tenant's. So a named read is
	// pinned to the tenant the app SERVES, while a write is not. A read that names no
	// row (e.Name == "") is a collection, whose tenant the list handler decides from
	// the same served org (principal.Scope) — the pin belongs on the row, not the
	// list, so this admits the collection and pins the item.
	if p.App != nil {
		if v == Read && e.Name != "" && e.Owner != p.Org {
			return false
		}
		return p.Holds(capFor(e.Kind), env)
	}
	// A person READS the projects and workspaces of every org they belong to.
	//
	// The tenant rule below admits a non-admin person exactly ONE entity — their own
	// user row — so without this a plain member cannot list the projects of their own
	// org, never mind a second one. Belonging is the authority here, and belonging is
	// a SET: an account lives in one tenant while the orgs someone works in are many,
	// so keying the read on the home org would also empty the console's switcher for
	// every member of an org they do not live in.
	//
	// Read only, and only these two kinds. A project is created, renamed and deleted
	// by the org's admin, whom p.Admin admits below; widening the verb would let
	// anyone ever added to an org delete its projects. Widening the kinds would reach
	// users, certs and applications, which belonging does not entitle you to see.
	// memberOf refuses an empty owner, so an unscoped read cannot slip through.
	if v == Read && (e.Kind == "projects" || e.Kind == "workspaces") && p.memberOf(e.Owner) {
		return true
	}
	if e.Owner == "" || e.Owner != p.Org {
		return false
	}
	if p.Admin {
		return true
	}
	return v == Read && e.Kind == "users" && e.Name != "" && e.Name == p.User
}

// Principal projects verified claims onto the decision's input — the ONE place a
// wire representation is read as authority, so no clause below reaches into a
// token.
//
// A machine's authority does not come through here: Sudo is false for a
// machine and for a confidential client by construction, so the projection cannot
// hand either the operator scope.
func (c *Claims) Principal() *Principal {
	if c == nil {
		return nil
	}
	p := &Principal{
		Org:   c.Owner,
		User:  c.Username(),
		Admin: c.IsAdmin,
		Sudo:  c.Sudo(),
		App:   c.App,
	}
	if len(c.Orgs) > 0 {
		p.Orgs = make(map[string]Role, len(c.Orgs))
		for _, m := range c.Orgs {
			p.Orgs[m.Org] = m.Role
		}
	}
	return p
}

// Holds reports whether these claims hold capability cap.
func (c *Claims) Holds(cap Cap, env Env) bool { return c.Principal().Holds(cap, env) }

// BoundTo reports whether the confidential client these claims authenticated as is
// bound to org by the <org>-<app> naming convention.
func (c *Claims) BoundTo(org string) bool { return c.Principal().BoundTo(org) }

// CanEntity reports whether these claims may v on the addressed registry row.
func (c *Claims) CanEntity(v Verb, e Entity, env Env) bool {
	return c.Principal().CanEntity(v, e, env)
}

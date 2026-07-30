// What an IAM token MEANS, published where the decision lives.
//
// IAM signs tokens in internal/oidc and published no way to read them, so every
// consumer wrote its own: gateway grew iamauth, cloud mirrored that (its own
// comment said so), tasks grew a third. Three readings of one contract, none
// owned by the issuer, all three in a different JWT library from the one that
// signs.
//
// They drifted, in the direction that matters. IsAdmin is IAM's ORG-level role
// bit; the edge minted the fleet's PLATFORM-authority header from it, so any org
// owner arrived as a platform admin — cross-org reads and the money gates. The
// meaning of a claim was never published by the party that assigns it, so a reader
// was free to guess, and one did.

package authz

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Membership is one org membership: the org, and the coarse role held in it. The
// JSON shape is the fixed claim contract — a token IAM mints and a consumer reads
// round-trips byte for byte.
type Membership struct {
	Org  string `json:"org"`
	Role Role   `json:"role,omitempty"`
}

// App is the confidential client a request authenticated as, resolved by IAM from
// its own application row. It is NOT a wire claim: a token cannot assert it, which
// is what keeps the capability gate below out of a caller's reach.
//
// An app principal is never a platform admin and never an org admin — its whole
// authority is the capability allowlist (entity.go), so a leaked client credential
// can neither read another tenant nor touch signing material.
type App struct {
	// Name is the application name — the key a capability allowlist is written in.
	Name string

	// Owner is the organization that OWNS the application row: a reserved platform
	// org for a platform console, the tenant's own org for a customer app. It is not
	// the org the application SERVES. A capability is granted only when this is a
	// reserved signing owner, so a tenant that registers an app whose name collides
	// with a platform console inherits none of its authority.
	Owner string

	// Cert is the name of the signing cert the application row references. It is
	// carried here so the self-read clause can admit an app exactly one cert — its
	// own — without the decision reaching into a store.
	Cert string
}

// Claims are the claims Hanzo IAM mints. internal/oidc signs THIS type, so the
// minter and every reader share one definition and cannot disagree about a
// field's name, presence or meaning.
type Claims struct {
	jwt.RegisteredClaims

	Scope        string `json:"scope,omitempty"`
	Organization string `json:"organization,omitempty"`
	Email        string `json:"email,omitempty"`
	Name         string `json:"name,omitempty"`

	// Owner is the org the subject BELONGS TO — the home org, the identity and
	// billing anchor. It is the platform-sudo signal (owner == AdminOrg) and is
	// NOT the same question as which org a request is acting in.
	Owner string `json:"owner,omitempty"`

	// PreferredUsername is the IAM USERNAME — the `<name>` half of
	// `<owner>/<name>`, e.g. "z" — not a display name. A consumer addressing a
	// wallet needs it: cloud's money path addresses `<org>/<username>`, and with
	// no username claim it fell back to `name` (a DisplayName) and addressed
	// `hanzo/Zach Kelling`, a wallet no funding path can name, while the balance
	// sat in `hanzo/z`. Every signed-in completion then 402'd on a funded account.
	PreferredUsername string `json:"preferred_username,omitempty"`

	// BillingAccount names WHICH LEDGER this token spends from. It is SIGNED, so
	// a caller cannot name its own payer — this is IAM stating who is entitled to
	// spend what. Empty is meaningful rather than missing: no explicit
	// entitlement, and the consumer keeps the behaviour it already had.
	BillingAccount string `json:"billing_account,omitempty"`

	// IsAdmin is IAM's ORG-level role bit: an org owner carries it within their
	// own org.
	//
	// IT IS NOT PLATFORM AUTHORITY, and reading it as such is a privilege
	// escalation. Gating the money/admin permission on it let any org owner
	// satisfy commerce's admin gates — unlimited free balance. Use PlatformSudo
	// for platform authority and OrgAdmin for this one; never this field directly.
	IsAdmin bool `json:"isAdmin,omitempty"`

	// Orgs is the membership set — every org the subject may act in, home org
	// first. A resource server authorizes an org-switch against it with no
	// round-trip. A machine token has no membership and omits the claim.
	Orgs []Membership `json:"orgs,omitempty"`

	Nonce     string `json:"nonce,omitempty"`
	Azp       string `json:"azp,omitempty"`
	TokenType string `json:"tokenType,omitempty"`

	// App is the confidential client the request authenticated as, or nil for a
	// human. IAM resolves it from its own application row and sets it after
	// verification; it is never decoded from the token, so `json:"-"`.
	App *App `json:"-"`
}

// AdminOrg is the reserved org slug IAM seeds PLATFORM (sudo) admins into.
//
// The org IS the capability. There is no separate superadmin boolean, because a
// flag beside the org is a second source of truth for one fact, and the two can
// disagree.
const AdminOrg = "admin"

// Machine reports whether these claims belong to a machine rather than a person.
//
// The signal is the MEMBERSHIP SET, because that is the one IAM guarantees. A
// person's token always carries at least their home org: store.MemberOrgRefs
// opens with {user.Owner, HomeRole(user)} before it appends anything else, so
// every user token IAM signs has a non-empty `orgs`. A client_credentials token
// carries none — IAM's own token.go says why, at the call that mints it: "a
// machine token has no user and therefore no membership set", so "an app token can
// never carry a tenancy it did not earn".
//
// This is not an inference about token shape, it is the semantics: authority here
// IS membership, and an identity with no memberships has none to hold.
//
// It fails closed. A user token whose membership set did not resolve reads as a
// machine and loses the two admin scopes; it does not gain them.
//
// An App principal is a confidential client by construction — IAM resolves it from
// its own application row after verification, so it is a statement rather than a
// claim, and it stands on its own.
//
// WHAT THIS REPLACES: `tokenType == "application"` and an owner-bound
// "<owner>-platform-kms" audience. IAM assigns `tokenType` exactly two values,
// "access-token" and "id-token" (internal/oidc/jwt.go), and never "application" —
// so the check could not fire, and every machine fell through to the audience
// clause, which only matches one identity in the estate. An admin-org
// client_credentials token therefore read as a HUMAN and PlatformSudo admitted it:
// cross-tenant reads plus the platform header the money gates trust. The tests
// covering it built their machine with the value IAM never mints, so they passed.
func (c *Claims) Machine() bool {
	if c == nil {
		return false
	}
	return c.App != nil || len(c.Orgs) == 0
}

// PlatformSudo reports platform authority: a HUMAN whose HOME org is the reserved
// admin org. It is the only cross-tenant scope — the one predicate every subsystem
// asks, so platform authority cannot mean two things in two places.
//
// The narrowing to a human is load-bearing in both directions. A machine token for
// admin/<anything> holds NO authority (IAM resolves platform sudo from a live user
// record in the admin org, never from a subject that merely names one), and a
// confidential client holds none either — its whole authority is its capability
// allowlist (entity.go). Without that, any admin-org client_credentials identity —
// the KMS sync app, say — could name a victim org and the edge would mint it,
// handing every backend that trusts the minted header a cross-tenant read.
//
// The org is compared VERBATIM, like every other org comparison here: folding case
// or space would make an org someone can self-serve ("Admin", "admin ") the
// reserved one, which is the whole escalation in a single strings call.
func (c *Claims) PlatformSudo() bool {
	if c == nil || c.Machine() {
		return false
	}
	return c.Owner == AdminOrg
}

// OrgAdmin reports whether these claims administer the named org — admin OF
// ONE'S OWN org, which is org-scoped self-service and NEVER platform authority.
//
// The org is compared VERBATIM. "acme" and "acme " are distinct identifiers to
// IAM, so a trim here would fold two tenants into one. The ROLE is folded by
// Role.Admits, which also folds owner into admin.
//
// A machine never administers an org through this predicate: a
// client_credentials app is issued for a purpose, not handed an org's
// self-service surface.
func (c *Claims) OrgAdmin(org string) bool {
	if c == nil || c.Machine() || org == "" {
		return false
	}
	if c.IsAdmin && org == c.Owner {
		return true
	}
	for _, m := range c.Orgs {
		if m.Org == org {
			return m.Role.Admits(Write)
		}
	}
	return false
}

// EffectiveOrg resolves WHICH ORG a request acts in: the org the client selected
// when the signed membership set admits it (or the operator may masquerade),
// otherwise the home org.
//
// It fails closed to home. A selected org outside the membership set is not an
// error to surface, it is simply not granted.
func (c *Claims) EffectiveOrg(selected string) (org string, switched bool) {
	if c == nil {
		return "", false
	}
	home := c.Owner
	if selected == "" || selected == home || HasUnsafeRune(selected) {
		return home, false
	}
	if c.PlatformSudo() {
		return selected, true
	}
	for _, m := range c.Orgs {
		if m.Org == selected {
			return selected, true
		}
	}
	return home, false
}

// UserID resolves the subject's stable identifier: `sub`, then the username,
// then the display name. IAM may leave `sub` empty on some token shapes.
func (c *Claims) UserID() string {
	if c == nil {
		return ""
	}
	for _, v := range []string{c.Subject, c.PreferredUsername, c.Name} {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// Username is the IAM username — the half a wallet address is built from. It
// never falls back to the display name, because addressing a wallet by a display
// name names a wallet nothing can fund.
func (c *Claims) Username() string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.PreferredUsername)
}

// Grants projects the signed membership set onto the grant model: a membership in
// an org IS a grant at that org's path. An org-wide member therefore needs no
// separate grant row, and the two representations cannot disagree.
//
// A membership whose org is not an injective identifier yields no grant — the same
// refusal EffectiveOrg makes, for the same reason.
func (c *Claims) Grants() []Grant {
	if c == nil {
		return nil
	}
	subject := c.UserID()
	if subject == "" {
		return nil
	}
	out := make([]Grant, 0, len(c.Orgs))
	for _, m := range c.Orgs {
		if m.Org == "" || HasUnsafeRune(m.Org) {
			continue
		}
		out = append(out, Grant{Subject: subject, Scope: Path{m.Org}, Role: m.Role})
	}
	return out
}

// Can reports whether these claims may v at target, given the grant set IAM holds
// for this subject. The caller supplies that set — this leaf holds no store.
//
// The signed membership set is folded in via Grants, so an org-wide member is
// authorized without a round-trip; grants adds everything narrower than an org
// (workspace, project, an invite-only project, a delegation to an agent).
//
// The platform operator is admitted anywhere, and only as a HUMAN: an admin-org
// machine identity is not a cross-tenant principal.
func (c *Claims) Can(v Verb, target Path, grants []Grant) bool {
	if c == nil {
		return false
	}
	if c.PlatformSudo() {
		return true
	}
	subject := c.UserID()
	return Can(subject, v, target, c.Grants()) || Can(subject, v, target, grants)
}

// signingOwners are the reserved platform organizations that own token-signing
// certificates. A signing cert is trusted ONLY under these owners, so a tenant
// can never shadow a platform signing key by creating a cert with the same name
// (the JWKS `kid`) under its own org and forging tokens.
var signingOwners = []string{AdminOrg, "built-in"}

// IsSigningOwner reports whether owner is a reserved platform signing-cert owner —
// the trust boundary the JWKS and token verification enforce, and the owner-pin a
// capability is granted under.
func IsSigningOwner(owner string) bool {
	for _, o := range signingOwners {
		if o == owner {
			return true
		}
	}
	return false
}

// serviceOrg is the system organization that owns service/app principals —
// reserved alongside the signing owners, but not itself a signing owner.
const serviceOrg = "app"

// IsReservedOrg reports whether owner is a SYSTEM organization a self-service,
// federated, or otherwise customer-driven flow may NEVER land a principal in. It
// is the ONE predicate that boundary shares, so the reserved set is defined in
// exactly one place and can never drift between those surfaces.
//
// The set is the platform-sudo/signing trust boundary — IsSigningOwner, composed
// so a newly-reserved signing owner is covered here for free — plus the
// service-principal org. A user created under any of these is a platform identity,
// not a customer. Fail-closed by construction: an unknown org is NOT reserved, so
// legitimate tenants are unaffected while every reserved org is refused.
func IsReservedOrg(owner string) bool {
	return IsSigningOwner(owner) || owner == serviceOrg
}

// HasUnsafeRune reports whether an identifier carries whitespace, a control rune
// or a format rune.
//
// An org, and every path segment below it, is a TENANCY key and must be
// injective: "acme " and "acme" are two strings a trim would fold into one —
// anywhere in the stack, including transport header handling — and folding two
// tenants together is a cross-tenant read. Such an identifier grants NOTHING; it
// is refused rather than cleaned, because cleaning IS the fold.
func HasUnsafeRune(s string) bool {
	for _, r := range s {
		switch {
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			return true
		case r < 0x20 || r == 0x7f:
			return true
		case r == 0x200b || r == 0x200c || r == 0x200d || r == 0xfeff:
			return true
		}
	}
	return false
}

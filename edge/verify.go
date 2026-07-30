// Verifying a credential at the edge: the leaf's rule, this package's keys, and
// the one policy the leaf deliberately declines.

package edge

import (
	"errors"
	"fmt"
	"time"

	"github.com/hanzoai/authz"
)

// ErrNoToken reports that no credential was present. It is distinct from an
// invalid one so a caller can fall through to a session or anonymous path instead
// of refusing — "absent" and "wrong" are different answers.
var ErrNoToken = errors.New("edge: no credential")

// Verifier is the whole credential check: the keys to verify against, the issuer to
// require, and the audiences this deployment accepts.
//
// It exists HERE, once, because every service that terminates identity needs
// exactly this and each one that wrote it again got it slightly wrong — one tried
// every key in the set rather than the one the token named, another skipped the
// issuer comparison whenever its configured issuer was empty. What legitimately
// differs per deployment is the VALUES (and the environment variable names they
// come from), so a deployment supplies those and nothing else.
type Verifier struct {
	keys *Keys

	// issuers is the trusted-issuer allowlist. One deployment fronts several brands
	// and each signs under its own issuer, so this is a SET; an empty one refuses
	// every token rather than silently disabling the check.
	issuers []string

	// audiences is the allowlist, with OR semantics: a token passes when its `aud`
	// matches ANY entry. EMPTY MEANS NO CHECK, deliberately.
	//
	// The check lives here rather than in authz.Verify because it is a POLICY, not
	// part of reading a token: IAM sets `aud` per RFC 8707 to the requesting CLIENT,
	// so the claim names which client asked for the token, not which resource server
	// may accept it. An edge may reasonably say "I accept tokens minted for these
	// consoles" — and a service that is itself a named audience checks the one value
	// it owns instead, which is what Claims.Machine does for the per-org KMS identity.
	audiences []string
}

// NewVerifier builds a Verifier. A non-positive ttl takes the key cache's default.
//
// The two lists are NOT symmetric, and the asymmetry is the point. An empty AUDIENCE
// list disables that check, because `aud` names the requesting client rather than the
// accepting server, so having no opinion about it is a coherent position. An empty
// ISSUER list refuses everything, because the issuer is who SIGNED the token and
// having no opinion about that is not a position, it is an open door.
func NewVerifier(jwksURL string, issuers, audiences []string, ttl time.Duration) *Verifier {
	return &Verifier{keys: NewKeys(jwksURL, ttl), issuers: issuers, audiences: audiences}
}

// Verify extracts the credential a request carries — Bearer, then HTTP Basic, then
// a session cookie — and verifies it.
func (v *Verifier) Verify(h Headers) (*authz.Claims, error) {
	return v.VerifyRaw(Token(h))
}

// VerifyRaw verifies a credential held out of band, such as the token an OAuth2
// code-exchange handler has just received.
//
// Signature, key id, algorithm, issuer and expiry are authz.Verify's; the audience
// allowlist is applied after. The order is not incidental: an unverified token's
// claims are evidence of nothing, so no claim is read off it before the signature
// holds.
func (v *Verifier) VerifyRaw(raw string) (*authz.Claims, error) {
	if v == nil {
		return nil, errors.New("edge: no verifier")
	}
	if raw == "" {
		return nil, ErrNoToken
	}
	claims, err := authz.Verify(raw, v.keys.Resolve, v.issuers)
	if err != nil {
		return nil, err
	}
	if len(v.audiences) == 0 {
		return claims, nil
	}
	for _, aud := range claims.Audience {
		for _, want := range v.audiences {
			// VERBATIM, like every identifier comparison in authz: folding case would
			// make two separately registered client ids one.
			if aud == want {
				return claims, nil
			}
		}
	}
	return nil, fmt.Errorf("edge: audience %v is not accepted here", []string(claims.Audience))
}

// Reading a token: the same library the issuer signs with.
//
// IAM signs in internal/oidc with golang-jwt/v5. The three readers that grew in
// its absence all used a different library, and a reader in a different library
// from the signer is free to disagree with it about what was signed. This one
// verifies exactly what IAM produces.

package authz

import (
	"crypto"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Keys resolves the public keys a token's `kid` may be verified against.
//
// Key material is an INPUT. Fetching a JWKS is I/O and must not live in a
// stateless leaf, or "stateless" quietly acquires a network dependency on the one
// path every request takes: the edge owns the fetch and the cache, and hands the
// result here. A nil Keys, or one that resolves nothing, verifies nothing.
type Keys func(kid string) []crypto.PublicKey

// algs are the JOSE `alg` values IAM's signer produces, and the only ones a token
// may be signed with: RSA and EC from methodForKey, plus ML-DSA-65 for a cert
// whose crypto algorithm is post-quantum. Anything else — `none`, an HMAC alg
// where a public key would be accepted as a secret, an alg IAM never emits — is
// refused before a signature is checked.
//
// MLDSA65 verifies only in a process that has registered that signing method; the
// alg being listed here does not itself supply a verifier, so a process without
// one fails closed rather than admitting an unverified token.
var algs = []string{"RS256", "RS512", "ES256", "ES384", "ES512", "MLDSA65"}

// leeway is the clock skew tolerated on exp and nbf, matching what the edge has
// been running with. Two spans of it is the widest a token's life can be stretched
// by disagreeing clocks.
const leeway = 2 * time.Minute

// Verify parses token, verifies its signature against the keys its `kid` names,
// and validates issuer and expiry. It returns the claims IAM signed.
//
// Verified: the algorithm (against algs, before any signature check), the `kid`
// (required — a token with no key id is refused rather than tried against every
// key in the set, which is how a reader ends up accepting a signature from a key
// the token never named), the signature, the issuer, and expiry with leeway. An
// empty expected issuer is an error, not a skipped comparison: jwt validates
// Issuer only when an expectation is set, so passing "" would accept a token from
// any issuer.
//
// The AUDIENCE is deliberately NOT verified. IAM sets aud per RFC 8707 to the
// requesting CLIENT (audienceFor: the client id, or "<clientId>-org-<org>" for a
// shared application, or an explicit resource indicator). It therefore names which
// client asked for the token, not which resource server may accept it — so a
// resource server checking it must enumerate every client id in the estate, and
// each new console 401s every user until someone adds it to a list. That list is
// exactly the drift this package exists to remove. The claim is returned in
// RegisteredClaims.Audience, so a service that IS a named audience (a per-org KMS
// identity checking "<owner>-platform-kms", which Machine already does) checks the
// one value it owns rather than maintaining a registry of everyone else's.
func Verify(token string, keys Keys, issuer string) (*Claims, error) {
	if token == "" {
		return nil, errors.New("authz: no token")
	}
	if keys == nil {
		return nil, errors.New("authz: no key material")
	}
	if issuer == "" {
		return nil, errors.New("authz: no expected issuer")
	}
	var c Claims
	_, err := jwt.ParseWithClaims(token, &c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("authz: token names no key id")
		}
		found := keys(kid)
		if len(found) == 0 {
			return nil, fmt.Errorf("authz: no key for id %q", kid)
		}
		set := jwt.VerificationKeySet{}
		for _, k := range found {
			set.Keys = append(set.Keys, k)
		}
		return set, nil
	},
		jwt.WithValidMethods(algs),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
	)
	if err != nil {
		return nil, fmt.Errorf("authz: %w", err)
	}
	return &c, nil
}

// IsAPIKey reports whether a credential is an opaque key rather than a JWT. It
// carries no claims and no signature to check, so it is resolved by IAM (which
// holds the key) and never parsed here.
func IsAPIKey(token string) bool {
	for _, p := range []string{"hk-", "sk-", "pk-", "fw_", "hz_"} {
		if strings.HasPrefix(token, p) {
			return true
		}
	}
	return false
}

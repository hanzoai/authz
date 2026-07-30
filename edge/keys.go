// Key custody: the edge fetches, the decision consumes.
//
// authz.Verify takes keys as an INPUT because a stateless leaf must not perform
// I/O on the path every request takes. Something has to do the fetching, and it is
// whoever holds the edge role — so it lives here, once, rather than as a JWKS
// reader per consumer.

package edge

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwks is the published key set, and key one key in it. Only the fields a
// verification key is built from are read; anything else in the document is
// ignored rather than refused, so a publisher adding a field does not break
// verification.
type jwks struct {
	Keys []key `json:"keys"`
}

type key struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// public materializes a JWK as a verification key.
//
// RSA and EC only — the two families IAM's methodForKey signs with. An unknown
// kty yields no key rather than an error, so one unreadable entry in a published
// set does not deny every token: the token's own kid either resolves to a usable
// key or it does not verify. IAM also publishes "MLDSA" for a post-quantum cert,
// which has no registered JWK representation to parse; it resolves to nothing
// here, which is the fail-closed answer rather than a silently unverified token.
func (k key) public() crypto.PublicKey {
	switch k.Kty {
	case "RSA":
		n, ok := unsigned(k.N)
		if !ok {
			return nil
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(raw) == 0 || len(raw) > 8 {
			return nil
		}
		e := 0
		for _, b := range raw {
			e = e<<8 | int(b)
		}
		// An even or unit exponent is not a usable RSA exponent, and a zero one makes
		// the key degenerate. Refuse rather than hand crypto/rsa something to divide by.
		if e < 3 || e%2 == 0 {
			return nil
		}
		return &rsa.PublicKey{N: n, E: e}
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil
		}
		x, okx := unsigned(k.X)
		y, oky := unsigned(k.Y)
		if !okx || !oky {
			return nil
		}
		// A point off the curve is not a key. Accepting one is the invalid-curve
		// attack, so the check is not optional.
		if !curve.IsOnCurve(x, y) {
			return nil
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	}
	return nil
}

// unsigned reads a base64url big-endian unsigned integer, the encoding every
// numeric JWK field uses.
func unsigned(s string) (*big.Int, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	return new(big.Int).SetBytes(raw), true
}

// Keys is the edge's JWKS cache: it fetches the published set, caches it for a
// TTL, and resolves a token's `kid` to the keys it may be verified against. It
// satisfies authz.Keys through Resolve.
//
// STALE ON ERROR. A publisher that is briefly unreachable must not 401 the estate,
// so a failed refresh keeps serving the keys already held. Signing keys are long
// lived and a rotation is additive, so serving a slightly old set costs at most one
// retry for a token signed under a brand-new key — where failing closed on every
// token would be an outage.
type Keys struct {
	url    string
	ttl    time.Duration
	client *http.Client

	mu      sync.RWMutex
	byKid   map[string][]crypto.PublicKey
	fetched time.Time
}

// NewKeys returns a cache for a JWKS URL. A non-positive ttl takes the default.
func NewKeys(url string, ttl time.Duration) *Keys {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &Keys{url: url, ttl: ttl, client: &http.Client{Timeout: 10 * time.Second}}
}

// Resolve returns the keys published under kid, refreshing past the TTL. It is
// the authz.Keys the decision consumes:
//
//	authz.Verify(token, keys.Resolve, issuer)
//
// An empty kid resolves nothing. Verify already refuses a token that names no key
// — trying every key in a set is how a reader ends up accepting a signature from a
// key the token never claimed — and this agrees with it rather than offering a
// second, looser path to the same question.
func (k *Keys) Resolve(kid string) []crypto.PublicKey {
	if k == nil || kid == "" {
		return nil
	}
	k.mu.RLock()
	fresh := k.byKid != nil && time.Since(k.fetched) < k.ttl
	found := k.byKid[kid]
	k.mu.RUnlock()
	if fresh {
		return found
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if k.byKid != nil && time.Since(k.fetched) < k.ttl {
		return k.byKid[kid] // another caller refreshed while this one waited
	}
	if set, err := k.fetch(); err == nil {
		k.byKid, k.fetched = set, time.Now()
	} else if k.byKid == nil {
		return nil
	}
	return k.byKid[kid]
}

// fetch reads the published set and indexes it by kid. A key with no kid is
// skipped: it can never be named by a token, so keeping it would only widen what
// an untargeted lookup could reach.
func (k *Keys) fetch() (map[string][]crypto.PublicKey, error) {
	resp, err := k.client.Get(k.url)
	if err != nil {
		return nil, fmt.Errorf("edge: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("edge: jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("edge: read jwks: %w", err)
	}
	var set jwks
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("edge: parse jwks: %w", err)
	}
	out := make(map[string][]crypto.PublicKey, len(set.Keys))
	for _, entry := range set.Keys {
		if entry.Kid == "" || (entry.Use != "" && entry.Use != "sig") {
			continue
		}
		if pub := entry.public(); pub != nil {
			out[entry.Kid] = append(out[entry.Kid], pub)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("edge: jwks published no usable signing key")
	}
	return out, nil
}

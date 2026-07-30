package edge_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/authz"
	"github.com/hanzoai/authz/edge"
)

// serveJWKS publishes a key set and reports how many times it was fetched.
func serveJWKS(t *testing.T, doc any) (url string, hits *int) {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// A token verifies against the published key its own kid names, end to end
// through the decision — the whole point of the split: the edge holds the keys,
// authz.Verify holds the rule.
func TestVerifyThroughPublishedRSAKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	url, hits := serveJWKS(t, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "cert-hanzo", "use": "sig",
		"n": b64u(priv.N.Bytes()), "e": b64u(big.NewInt(int64(priv.E)).Bytes()),
	}}})

	claims := &authz.Claims{Owner: "acme", PreferredUsername: "alice",
		Orgs: []authz.Membership{{Org: "acme", Role: authz.Member}}}
	claims.Issuer = "https://hanzo.id"
	claims.Subject = "uuid-alice"
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "cert-hanzo"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	keys := edge.NewKeys(url, time.Minute)
	got, err := authz.Verify(signed, keys.Resolve, "https://hanzo.id")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Owner != "acme" {
		t.Errorf("owner = %q, want acme", got.Owner)
	}

	// The second verification is served from cache — the fetch is per TTL, not per
	// request, or the edge adds a network round-trip to every call it fronts.
	if _, err := authz.Verify(signed, keys.Resolve, "https://hanzo.id"); err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	if *hits != 1 {
		t.Errorf("fetched the JWKS %d times, want 1", *hits)
	}
}

// A token signed by a key the publisher never published does not verify, however
// well-formed it is. This is the forged-issuer case.
func TestForeignKeyDoesNotVerify(t *testing.T) {
	published, _ := rsa.GenerateKey(rand.Reader, 2048)
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	url, _ := serveJWKS(t, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "cert-hanzo", "use": "sig",
		"n": b64u(published.N.Bytes()), "e": b64u(big.NewInt(int64(published.E)).Bytes()),
	}}})

	claims := &authz.Claims{Owner: authz.AdminOrg, PreferredUsername: "root",
		Orgs: []authz.Membership{{Org: authz.AdminOrg, Role: authz.Admin}}}
	claims.Issuer = "https://hanzo.id"
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "cert-hanzo" // names the real key, signed with another
	signed, _ := tok.SignedString(attacker)

	keys := edge.NewKeys(url, time.Minute)
	if _, err := authz.Verify(signed, keys.Resolve, "https://hanzo.id"); err == nil {
		t.Fatal("a token signed by an unpublished key verified")
	}
}

// An EC point that is not on the named curve is not a key. Materializing one is
// the invalid-curve attack, so it must resolve to nothing.
func TestPointOffTheCurveIsNotAKey(t *testing.T) {
	good, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	url, _ := serveJWKS(t, map[string]any{"keys": []map[string]any{
		{"kty": "EC", "kid": "off-curve", "crv": "P-256",
			"x": b64u(good.X.Bytes()), "y": b64u(new(big.Int).Add(good.Y, big.NewInt(1)).Bytes())},
		{"kty": "EC", "kid": "on-curve", "crv": "P-256",
			"x": b64u(good.X.Bytes()), "y": b64u(good.Y.Bytes())},
	}})

	keys := edge.NewKeys(url, time.Minute)
	if got := keys.Resolve("off-curve"); len(got) != 0 {
		t.Errorf("a point off the curve resolved to %d keys", len(got))
	}
	if got := keys.Resolve("on-curve"); len(got) != 1 {
		t.Errorf("a valid EC key resolved to %d keys, want 1", len(got))
	}
}

// A degenerate RSA exponent is refused rather than handed to crypto/rsa, and an
// unknown key type resolves to nothing without denying the rest of the set.
func TestUnusableKeysAreSkippedWithoutDenyingTheSet(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	url, _ := serveJWKS(t, map[string]any{"keys": []map[string]any{
		{"kty": "RSA", "kid": "even-exponent", "n": b64u(priv.N.Bytes()), "e": b64u([]byte{4})},
		{"kty": "RSA", "kid": "unit-exponent", "n": b64u(priv.N.Bytes()), "e": b64u([]byte{1})},
		{"kty": "MLDSA", "kid": "post-quantum", "x": b64u([]byte("raw"))},
		{"kty": "RSA", "kid": "no-kid-sibling", "n": b64u(priv.N.Bytes()), "e": b64u(big.NewInt(int64(priv.E)).Bytes())},
	}})

	keys := edge.NewKeys(url, time.Minute)
	for _, kid := range []string{"even-exponent", "unit-exponent", "post-quantum"} {
		if got := keys.Resolve(kid); len(got) != 0 {
			t.Errorf("%s resolved to %d keys, want none", kid, len(got))
		}
	}
	if got := keys.Resolve("no-kid-sibling"); len(got) != 1 {
		t.Errorf("the usable key resolved to %d keys, want 1 — one bad entry denied the set", len(got))
	}
	// An unnamed key can never be reached by a token, so it is not indexed at all.
	if got := keys.Resolve(""); got != nil {
		t.Error("an empty kid resolved to a key")
	}
}

// An unreachable publisher must not 401 the estate: a failed refresh keeps serving
// what is already held. Failing closed on every token would turn one publisher
// blip into an outage.
func TestStaleKeysSurviveAFailedRefresh(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	up := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "cert-hanzo", "use": "sig",
			"n": b64u(priv.N.Bytes()), "e": b64u(big.NewInt(int64(priv.E)).Bytes()),
		}}})
	}))
	defer srv.Close()

	keys := edge.NewKeys(srv.URL, time.Nanosecond) // every lookup refreshes
	if len(keys.Resolve("cert-hanzo")) != 1 {
		t.Fatal("the first fetch resolved no key")
	}
	up = false
	if len(keys.Resolve("cert-hanzo")) != 1 {
		t.Error("a failed refresh dropped keys that were already held")
	}
}

// With no keys ever held, a failed fetch resolves nothing — the honest answer, and
// the one that denies rather than admits.
func TestNoKeysMeansNoVerification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	keys := edge.NewKeys(srv.URL, time.Minute)
	if got := keys.Resolve("cert-hanzo"); got != nil {
		t.Error("an unreachable publisher resolved a key")
	}
	if _, err := authz.Verify("not.a.token", keys.Resolve, "https://hanzo.id"); err == nil {
		t.Error("verification succeeded with no key material")
	}
}

// The Verifier is the whole check in one place: keys, issuer, audience. These are
// the two mistakes each hand-written copy made — one tried every key in the set
// instead of the one the token named, another skipped the issuer comparison when its
// configured issuer was empty.
func TestVerifierRefusesWhatTheCopiesAccepted(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	url, _ := serveJWKS(t, map[string]any{"keys": []map[string]any{
		{"kty": "RSA", "kid": "cert-hanzo", "use": "sig",
			"n": b64u(priv.N.Bytes()), "e": b64u(big.NewInt(int64(priv.E)).Bytes())},
		{"kty": "RSA", "kid": "cert-other", "use": "sig",
			"n": b64u(other.N.Bytes()), "e": b64u(big.NewInt(int64(other.E)).Bytes())},
	}})

	mint := func(key *rsa.PrivateKey, kid, issuer, aud string) string {
		c := &authz.Claims{Owner: "acme", PreferredUsername: "alice",
			Orgs: []authz.Membership{{Org: "acme", Role: authz.Member}}}
		c.Issuer = issuer
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
		if aud != "" {
			c.Audience = []string{aud}
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
		if kid != "" {
			tok.Header["kid"] = kid
		}
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	v := edge.NewVerifier(url, "https://hanzo.id", []string{"hanzo-console"}, time.Minute)

	if _, err := v.VerifyRaw(mint(priv, "cert-hanzo", "https://hanzo.id", "hanzo-console")); err != nil {
		t.Fatalf("a good token was refused: %v", err)
	}

	// Signed by a key that IS published, but under a kid the token does not name.
	// A reader that loops over every key in the set accepts this; naming a key is
	// the whole point of `kid`.
	if _, err := v.VerifyRaw(mint(other, "cert-hanzo", "https://hanzo.id", "hanzo-console")); err == nil {
		t.Error("a token verified against a key it did not name")
	}
	// No kid at all — refused rather than tried against the set.
	if _, err := v.VerifyRaw(mint(priv, "", "https://hanzo.id", "hanzo-console")); err == nil {
		t.Error("a token naming no key verified")
	}
	// A foreign issuer.
	if _, err := v.VerifyRaw(mint(priv, "cert-hanzo", "https://evil.test", "hanzo-console")); err == nil {
		t.Error("a foreign issuer verified")
	}
	// An audience outside the allowlist.
	if _, err := v.VerifyRaw(mint(priv, "cert-hanzo", "https://hanzo.id", "someone-elses-app")); err == nil {
		t.Error("an unaccepted audience verified")
	}
	// Absent is distinct from invalid, so a caller can fall through instead of refusing.
	if _, err := v.VerifyRaw(""); !errors.Is(err, edge.ErrNoToken) {
		t.Errorf("an absent credential gave %v, want ErrNoToken", err)
	}

	// An EMPTY configured issuer must refuse everything. The copies made this a
	// skipped comparison, which accepts a token from any issuer.
	blind := edge.NewVerifier(url, "", nil, time.Minute)
	if _, err := blind.VerifyRaw(mint(priv, "cert-hanzo", "https://evil.test", "")); err == nil {
		t.Error("a verifier with no configured issuer accepted a foreign one")
	}

	// The credential is read off the request too, not only passed in raw.
	h := http.Header{}
	h.Set("Authorization", "Bearer "+mint(priv, "cert-hanzo", "https://hanzo.id", "hanzo-console"))
	if _, err := v.Verify(h); err != nil {
		t.Errorf("Verify(Headers): %v", err)
	}
}

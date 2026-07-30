package edge_test

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/hanzoai/authz"
	"github.com/hanzoai/authz/edge"
)

// net/http's own header type satisfies edge.Headers with NO adapter — the reason
// the rules take an interface rather than a transport. If this stops compiling, an
// HTTP edge has to write its own applier again, which is how the two drifted.
var _ edge.Headers = http.Header{}

// THE ANTI-DRIFT TEST. Both transports must produce a byte-identical identity from
// identical claims. This is the property whose absence let the platform header be
// corrected in one edge while the other went on minting it from an org role.
func TestBothTransportsMintTheSameIdentity(t *testing.T) {
	cl := &authz.Claims{
		Owner: "acme", PreferredUsername: "founder", Name: "Founder",
		Email: "f@acme.test", IsAdmin: true, BillingAccount: "org:acme",
		Workspace: "prod", Project: "web",
		Orgs: []authz.Membership{{Org: "acme", Role: authz.Owner}, {Org: "beta", Role: authz.Member}},
	}
	cl.Subject = "uuid-founder"

	for _, selected := range []string{"", "beta", "victim"} {
		zipped := req(t)
		edge.Apply(edge.Of(&zipped.Fiber().Request().Header), cl, selected, nil)

		plain := http.Header{}
		edge.Apply(plain, cl, selected, nil)

		for _, name := range append(append([]string{}, authz.Headers...), authz.Retired...) {
			z, p := hdr(zipped, name), plain.Get(name)
			if z != p {
				t.Errorf("selected=%q: %s is %q on zip and %q on net/http", selected, name, z, p)
			}
		}
	}
}

// Strip works the same on both, including the claimed-org capture.
func TestBothTransportsStripTheSame(t *testing.T) {
	zipped := req(t)
	plain := http.Header{}
	for _, name := range append(append([]string{}, authz.Headers...), authz.Retired...) {
		edge.Of(&zipped.Fiber().Request().Header).Set(name, "forged")
		plain.Set(name, "forged")
	}
	edge.Of(&zipped.Fiber().Request().Header).Set(authz.HeaderOrg, "claimed")
	plain.Set(authz.HeaderOrg, "claimed")

	if z, p := edge.Strip(edge.Of(&zipped.Fiber().Request().Header)), edge.Strip(plain); z != p || z != "claimed" {
		t.Fatalf("Strip returned %q on zip and %q on net/http, want claimed", z, p)
	}
	for _, name := range append(append([]string{}, authz.Headers...), authz.Retired...) {
		if z, p := hdr(zipped, name), plain.Get(name); z != "" || p != "" {
			t.Errorf("%s survived: zip=%q net/http=%q", name, z, p)
		}
	}
}

// The un-shadowable cookie wins, and a duplicate name takes the FIRST value: a
// later one is what someone who can set a cookie on a sibling host appends, and
// last-wins would let it overwrite the real session.
func TestCookiePrecedenceAndFirstWins(t *testing.T) {
	for _, c := range []struct{ name, jar, want string }{
		{"host prefix wins over unprefixed", "hanzo_token=weak; __Host-hanzo_iam_token=strong", "strong"},
		{"first value of a duplicated name wins", "access_token=real; access_token=appended", "real"},
		{"quoted values are unwrapped", `access_token="quoted"`, "quoted"},
		// A pair may be padded — after splitting on ";" every pair but the first carries a
		// leading space — but the NAME is matched verbatim. Trimming the name would make
		// " access_token" and "access_token" one cookie, which is the same fold every
		// identifier rule here refuses; a conformant client never pads around "=".
		{"a padded pair is read", " access_token=padded ", "padded"},
		{"a padded NAME is a different name", "access_token = spaced", ""},
		{"an empty value is not a credential", "access_token=; hanzo_token=fallback", "fallback"},
		{"an unrelated jar yields nothing", "theme=dark; lang=en", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{"Cookie": []string{c.jar}}
			if got := edge.Cookie(h); got != c.want {
				t.Errorf("Cookie(%q) = %q, want %q", c.jar, got, c.want)
			}
		})
	}
}

// The credential is read in one order on both transports: Bearer, then Basic, then
// the cookie. A proxy sending a .netrc credential must not be shadowed by a stale
// browser cookie, and a Bearer must beat both.
func TestCredentialPrecedence(t *testing.T) {
	basic := "Basic " + base64Basic("z@hanzo.ai", "from-netrc")
	for _, c := range []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"bearer beats everything", map[string]string{
			"Authorization": "Bearer from-bearer", "Cookie": "access_token=from-cookie"}, "from-bearer"},
		{"basic beats the cookie", map[string]string{
			"Authorization": basic, "Cookie": "access_token=from-cookie"}, "from-netrc"},
		{"the cookie is the fallback", map[string]string{
			"Cookie": "access_token=from-cookie"}, "from-cookie"},
		{"x-authorization is read when authorization is absent", map[string]string{
			"X-Authorization": "Bearer from-x"}, "from-x"},
		{"nothing at all is empty", nil, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range c.headers {
				h.Set(k, v)
			}
			if got := edge.Token(h); got != c.want {
				t.Errorf("Token = %q, want %q", got, c.want)
			}
		})
	}
}

func base64Basic(user, pass string) string {
	return b64std(user + ":" + pass)
}

func b64std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Both header shapes qualify by SHAPE, and neither transport is named in the
// package. net/http's type satisfies edge.Headers directly (asserted above);
// fasthttp's byte-returning shape satisfies edge.Peeker, which is what a zip request
// is handed through. If either assertion needs an import from a web framework to
// compile, the edge has re-acquired a transport dependency and every consumer pays
// for it — the edge went from 318 linked packages to 190 by dropping exactly that.
type bytesHeader struct{ m map[string]string }

func (b bytesHeader) Peek(name string) []byte { return []byte(b.m[name]) }
func (b bytesHeader) Set(name, value string)  { b.m[name] = value }
func (b bytesHeader) Del(name string)         { delete(b.m, name) }

var _ edge.Peeker = bytesHeader{}

// And a byte-returning header set behaves identically to net/http's through the
// same rules — the adapter is not a second implementation.
func TestPeekerShapeMatchesNetHTTP(t *testing.T) {
	cl := &authz.Claims{Owner: "acme", PreferredUsername: "alice", Email: "a@acme.test",
		Orgs: []authz.Membership{{Org: "acme", Role: authz.Member}}}

	bytes := edge.Of(bytesHeader{m: map[string]string{}})
	plain := http.Header{}
	edge.Apply(bytes, cl, "", nil)
	edge.Apply(plain, cl, "", nil)

	for _, name := range authz.Headers {
		if b, p := bytes.Get(name), plain.Get(name); b != p {
			t.Errorf("%s is %q through Peeker and %q through net/http", name, b, p)
		}
	}
}

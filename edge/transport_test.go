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
		edge.Inject(edge.Of(zipped), cl, selected, nil)

		plain := http.Header{}
		edge.Inject(plain, cl, selected, nil)

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
		edge.Of(zipped).Set(name, "forged")
		plain.Set(name, "forged")
	}
	edge.Of(zipped).Set(authz.HeaderOrg, "claimed")
	plain.Set(authz.HeaderOrg, "claimed")

	if z, p := edge.Strip(edge.Of(zipped)), edge.Strip(plain); z != p || z != "claimed" {
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

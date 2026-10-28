package serve_test

// The /v1/authz surface is the network edge of the access decision: every
// cross-tenant refusal and every fail-closed branch lives here and had no
// tests. These exercise the mounted routes end to end through zip's in-process
// test transport, the way the gateway calls them.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/hanzoai/authz/serve"
	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

func mounted(t *testing.T) *zip.App {
	t.Helper()
	app := zip.New(zip.Config{AppName: "authz-servetest"})
	if err := serve.Use(app, luxlog.New("component", "authz-servetest")); err != nil {
		t.Fatalf("mount: %v", err)
	}
	return app
}

// check posts body to /v1/authz/check with the caller's org header set the way
// the gateway writes it, and returns the status and decoded response.
func check(t *testing.T, app *zip.App, org, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/v1/authz/check", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if org != "" {
		req.Header.Set("X-Org-Id", org)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func grant(subject, scope, role string, expiry time.Time) map[string]any {
	g := map[string]any{"subject": subject, "scope": scope, "role": role}
	if !expiry.IsZero() {
		g["expiry"] = expiry.UTC().Format(time.RFC3339)
	}
	return g
}

func body(subject, verb, path string, grants ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"subject": subject, "verb": verb, "path": path, "grants": grants,
	})
	return string(b)
}

func TestHealth(t *testing.T) {
	app := mounted(t)
	req, _ := http.NewRequest(http.MethodGet, "/v1/authz/health", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d, want 200", resp.StatusCode)
	}
}

func TestCheckRefusesMissingOrg(t *testing.T) {
	app := mounted(t)
	status, _ := check(t, app, "", body("u1", "read", "acme/prod",
		grant("u1", "acme", "owner", time.Time{})))
	if status != http.StatusUnauthorized {
		t.Fatalf("no org header = %d, want 401", status)
	}
}

func TestCheckRefusesCrossTenantTarget(t *testing.T) {
	app := mounted(t)
	status, _ := check(t, app, "acme", body("u1", "read", "beta/prod",
		grant("u1", "beta", "owner", time.Time{})))
	if status != http.StatusForbidden {
		t.Fatalf("cross-tenant target = %d, want 403", status)
	}
}

func TestCheckRefusesCrossTenantGrantScope(t *testing.T) {
	app := mounted(t)
	status, _ := check(t, app, "acme", body("u1", "read", "acme/prod",
		grant("u1", "beta", "owner", time.Time{})))
	if status != http.StatusForbidden {
		t.Fatalf("cross-tenant grant scope = %d, want 403", status)
	}
}

func TestCheckRefusesMalformedPath(t *testing.T) {
	app := mounted(t)
	status, _ := check(t, app, "acme", body("u1", "read", "acme//prod",
		grant("u1", "acme", "owner", time.Time{})))
	if status != http.StatusBadRequest {
		t.Fatalf("empty path segment = %d, want 400", status)
	}
}

func TestCheckRefusesMissingFields(t *testing.T) {
	app := mounted(t)
	status, _ := check(t, app, "acme", `{"subject":"u1","verb":"read","grants":[]}`)
	if status != http.StatusBadRequest {
		t.Fatalf("missing path = %d, want 400", status)
	}
}

func TestCheckAllowsOwnerWrite(t *testing.T) {
	app := mounted(t)
	status, out := check(t, app, "acme", body("u1", "write", "acme/prod/web",
		grant("u1", "acme", "owner", time.Time{})))
	if status != http.StatusOK || out["allow"] != true {
		t.Fatalf("owner write = %d %v, want 200 allow:true", status, out)
	}
}

func TestCheckNarrowsByPrefix(t *testing.T) {
	app := mounted(t)
	// A grant at acme/prod reaches acme/prod/web but not acme/other.
	status, out := check(t, app, "acme", body("u1", "write", "acme/prod/web",
		grant("u1", "acme/prod", "admin", time.Time{})))
	if status != http.StatusOK || out["allow"] != true {
		t.Fatalf("narrower-scope grant at covered path = %d %v, want allow:true", status, out)
	}
	status, out = check(t, app, "acme", body("u1", "write", "acme/other",
		grant("u1", "acme/prod", "admin", time.Time{})))
	if status != http.StatusOK || out["allow"] != false {
		t.Fatalf("narrower-scope grant at sibling path = %d %v, want allow:false", status, out)
	}
}

func TestCheckDeniesMemberWrite(t *testing.T) {
	app := mounted(t)
	status, out := check(t, app, "acme", body("u1", "write", "acme/prod",
		grant("u1", "acme", "member", time.Time{})))
	if status != http.StatusOK || out["allow"] != false {
		t.Fatalf("member write = %d %v, want allow:false", status, out)
	}
	status, out = check(t, app, "acme", body("u1", "read", "acme/prod",
		grant("u1", "acme", "member", time.Time{})))
	if status != http.StatusOK || out["allow"] != true {
		t.Fatalf("member read = %d %v, want allow:true", status, out)
	}
}

func TestCheckDeniesExpiredGrant(t *testing.T) {
	app := mounted(t)
	status, out := check(t, app, "acme", body("u1", "write", "acme/prod",
		grant("u1", "acme", "owner", time.Now().Add(-time.Minute))))
	if status != http.StatusOK || out["allow"] != false {
		t.Fatalf("expired grant = %d %v, want allow:false", status, out)
	}
}

func TestCheckDeniesUnknownVerbAndRole(t *testing.T) {
	app := mounted(t)
	status, out := check(t, app, "acme", body("u1", "delete", "acme/prod",
		grant("u1", "acme", "owner", time.Time{})))
	if status != http.StatusOK || out["allow"] != false {
		t.Fatalf("unknown verb = %d %v, want allow:false (fail closed)", status, out)
	}
	status, out = check(t, app, "acme", body("u1", "read", "acme/prod",
		grant("u1", "acme", "superuser", time.Time{})))
	if status != http.StatusOK || out["allow"] != false {
		t.Fatalf("unknown role = %d %v, want allow:false (fail closed)", status, out)
	}
}

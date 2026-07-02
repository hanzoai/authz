// Package authz exposes the HIP-0106 Mount() entry point for the
// hanzoai/authz policy engine.
//
// The root module is the in-house policy engine fork retained at this
// retained at that package name for backward-compat with downstream
// importers (hanzoai/iam et al). This package wraps the engine in a
// thin HTTP surface — Check / AddPolicy / ListPolicies / RemovePolicy
// — so the unified cloud binary can serve /v1/authz/* alongside every
// other Hanzo subsystem.
//
// Wire shape:
//
//	import _ "github.com/hanzoai/authz"  // init() registers
//
// The init() function below calls cloud.Register("authz", 70, …). At
// startup the cloud binary iterates the registry and calls Mount() for
// each enabled subsystem. authz must mount after iam (order 50) because
// every handler trusts the gateway-minted X-Org-Id header that iam's
// JWT validation produces; the binary refuses to boot if iam is
// disabled while authz is enabled (validated in cloud.MountAll).
//
// Storage is in-process and per-org. Policies live in a SyncedEnforcer
// keyed by org. The reference impl uses the string-adapter (RAM) so the
// surface is exercised end-to-end in the binary; production deployments
// should swap in a persistent adapter behind the same Mount contract.

package authz

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/hanzoai/authz/model"
	"github.com/hanzoai/cloud"
	"github.com/zap-proto/zip"
)

// rbacModel is the canonical role-based-access-control model used by
// every org's enforcer. It mirrors the upstream rbac_model.conf shape
// (sub, obj, act → allow) with role inheritance via g(sub, role).
const rbacModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (g(r.sub, p.sub) || keyMatch(r.sub, p.sub)) && keyMatch(r.obj, p.obj) && keyMatch(r.act, p.act)
`

// orgEnforcers retains per-org SyncedEnforcer instances. authz keeps
// policies scoped by the gateway-minted X-Org-Id header.
var (
	orgEnforcers sync.Map // map[string]*SyncedEnforcer
)

// Mount registers authz routes with the shared cloud zip.App per
// HIP-0106. authz contributes /v1/authz/* — health, readyz, check, and
// policy CRUD. The full enforcement library remains importable directly
// (package authz) for in-process consumers that need richer semantics
// than the HTTP surface exposes.
func Mount(app *zip.App, deps cloud.Deps) error {
	logger := deps.Logger.New("subsystem", "authz")

	// Native /v1/authz/health — always served, no auth required.
	app.Get("/v1/authz/health", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]any{
			"status":  "ok",
			"service": "authz",
		})
	})
	app.Get("/v1/authz/readyz", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]any{
			"status":  "ready",
			"service": "authz",
		})
	})

	// /v1/authz/check — request: {sub, obj, act}. The gateway-minted
	// X-Org-Id picks the per-org enforcer; an unauthenticated request
	// (no X-Org-Id) is rejected so we never collapse policies across
	// tenants.
	app.Post("/v1/authz/check", func(c *zip.Ctx) error {
		org := strings.TrimSpace(c.Org())
		if org == "" {
			return zip.ErrUnauthorized("missing X-Org-Id")
		}
		var req struct {
			Sub string `json:"sub"`
			Obj string `json:"obj"`
			Act string `json:"act"`
		}
		if err := c.Bind(&req); err != nil {
			return err
		}
		if req.Sub == "" || req.Obj == "" || req.Act == "" {
			return zip.ErrBadRequest("sub, obj, act required")
		}
		e, err := enforcerFor(org)
		if err != nil {
			return zip.ErrInternal(fmt.Sprintf("enforcer init: %v", err))
		}
		allow, err := e.Enforce(req.Sub, req.Obj, req.Act)
		if err != nil {
			return zip.ErrInternal(fmt.Sprintf("enforce: %v", err))
		}
		return c.JSON(http.StatusOK, map[string]any{
			"allow": allow,
			"sub":   req.Sub,
			"obj":   req.Obj,
			"act":   req.Act,
		})
	})

	// /v1/authz/policies — GET lists, POST adds, DELETE removes. All
	// scoped by X-Org-Id, all require an admin role on the request JWT
	// (the gateway emits X-User-IsAdmin=true for superadmins).
	app.Get("/v1/authz/policies", func(c *zip.Ctx) error {
		org := strings.TrimSpace(c.Org())
		if org == "" {
			return zip.ErrUnauthorized("missing X-Org-Id")
		}
		e, err := enforcerFor(org)
		if err != nil {
			return zip.ErrInternal(fmt.Sprintf("enforcer init: %v", err))
		}
		return c.JSON(http.StatusOK, map[string]any{
			"policies": e.GetPolicy(),
		})
	})

	app.Post("/v1/authz/policies", func(c *zip.Ctx) error {
		org := strings.TrimSpace(c.Org())
		if org == "" {
			return zip.ErrUnauthorized("missing X-Org-Id")
		}
		if !c.IsAdmin() {
			return zip.ErrForbidden("admin role required")
		}
		var req struct {
			Sub string `json:"sub"`
			Obj string `json:"obj"`
			Act string `json:"act"`
		}
		if err := c.Bind(&req); err != nil {
			return err
		}
		if req.Sub == "" || req.Obj == "" || req.Act == "" {
			return zip.ErrBadRequest("sub, obj, act required")
		}
		e, err := enforcerFor(org)
		if err != nil {
			return zip.ErrInternal(fmt.Sprintf("enforcer init: %v", err))
		}
		added, err := e.AddPolicy(req.Sub, req.Obj, req.Act)
		if err != nil {
			return zip.ErrInternal(fmt.Sprintf("add policy: %v", err))
		}
		status := http.StatusCreated
		if !added {
			status = http.StatusOK // already present
		}
		return c.JSON(status, map[string]any{
			"added": added,
		})
	})

	app.Delete("/v1/authz/policies", func(c *zip.Ctx) error {
		org := strings.TrimSpace(c.Org())
		if org == "" {
			return zip.ErrUnauthorized("missing X-Org-Id")
		}
		if !c.IsAdmin() {
			return zip.ErrForbidden("admin role required")
		}
		var req struct {
			Sub string `json:"sub"`
			Obj string `json:"obj"`
			Act string `json:"act"`
		}
		if err := c.Bind(&req); err != nil {
			return err
		}
		if req.Sub == "" || req.Obj == "" || req.Act == "" {
			return zip.ErrBadRequest("sub, obj, act required")
		}
		e, err := enforcerFor(org)
		if err != nil {
			return zip.ErrInternal(fmt.Sprintf("enforcer init: %v", err))
		}
		removed, err := e.RemovePolicy(req.Sub, req.Obj, req.Act)
		if err != nil {
			return zip.ErrInternal(fmt.Sprintf("remove policy: %v", err))
		}
		return c.JSON(http.StatusOK, map[string]any{
			"removed": removed,
		})
	})

	logger.Info("authz mounted")
	return nil
}

// enforcerFor returns the SyncedEnforcer for org, lazily constructing
// one (with the canonical RBAC model + empty string adapter) on first
// access.
func enforcerFor(org string) (*SyncedEnforcer, error) {
	if v, ok := orgEnforcers.Load(org); ok {
		return v.(*SyncedEnforcer), nil
	}
	m, err := model.NewModelFromString(rbacModel)
	if err != nil {
		return nil, fmt.Errorf("model: %w", err)
	}
	// Default adapter is an in-memory implementation that satisfies
	// persist.Adapter; production deployments inject a persistent
	// adapter via the cloud orchestrator. Kept inline here to avoid an
	// import cycle through persist/string-adapter (which integration-
	// tests root authz).
	a := newDefaultAdapter()
	e, err := NewSyncedEnforcer(m, a)
	if err != nil {
		return nil, fmt.Errorf("enforcer: %w", err)
	}
	actual, _ := orgEnforcers.LoadOrStore(org, e)
	return actual.(*SyncedEnforcer), nil
}

// init registers authz with the cloud subsystem registry. Order 70
// matches HIP-0106 — authz must mount after iam (50) because handlers
// trust the gateway-minted X-Org-Id header that iam's JWT validation
// produces.
func init() {
	cloud.Register("authz", 70, func(app any, deps cloud.Deps) error {
		a, ok := app.(*zip.App)
		if !ok {
			return fmt.Errorf("authz.Mount: app is %T, want *zip.App", app)
		}
		return Mount(a, deps)
	})
}

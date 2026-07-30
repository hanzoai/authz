// Package serve is the network surface over the decision, and nothing else.
//
// It is a SEPARATE package because the decision leaf must stay pure: a caller
// importing github.com/hanzoai/authz links no HTTP stack, no driver, no socket, so
// adding a caller costs nothing. Speaking HTTP is I/O, and I/O lives here.
package serve

import (
	"net/http"
	"time"

	"github.com/hanzoai/authz"
	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

// Mount registers /v1/authz/* on the shared cloud app (HIP-0106).
//
// It takes only the canonical logger — the surface has no other dependency on the
// host, so this stays a standalone module and cloud's composition root adapts its
// own dependencies by passing the one thing needed.
//
// The surface is STATELESS, like the decision it exposes: a check carries the
// grants it is to be decided against. There is no policy store and no policy CRUD
// here, because the grant SET belongs to IAM — IAM signs it, so IAM owns it, and a
// second writable copy behind this surface would be a second source of truth for
// who may do what.
func Mount(app *zip.App, logger luxlog.Logger) error {
	logger = logger.New("subsystem", "authz")

	app.Get("/v1/authz/health", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]any{"status": "ok", "service": "authz"})
	})
	app.Get("/v1/authz/readyz", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]any{"status": "ready", "service": "authz"})
	})

	// POST /v1/authz/check — {subject, verb, path, grants} -> {allow}.
	//
	// The caller's own org scopes the question: every grant is read at or below it,
	// so one tenant can never have a decision made for it in another tenant's request.
	// An unauthenticated request carries no org and is refused rather than decided
	// against an empty scope.
	app.Post("/v1/authz/check", func(c *zip.Ctx) error {
		org := c.Org()
		if org == "" || authz.HasUnsafeRune(org) {
			return zip.ErrUnauthorized("missing X-Org-Id")
		}
		var req struct {
			Subject string `json:"subject"`
			Verb    string `json:"verb"`
			Path    string `json:"path"`
			Grants  []struct {
				Subject string    `json:"subject"`
				Scope   string    `json:"scope"`
				Role    string    `json:"role"`
				Expiry  time.Time `json:"expiry"`
			} `json:"grants"`
		}
		if err := c.Bind(&req); err != nil {
			return err
		}
		if req.Subject == "" || req.Verb == "" || req.Path == "" {
			return zip.ErrBadRequest("subject, verb, path required")
		}
		target, err := authz.ParsePath(req.Path)
		if err != nil {
			return zip.ErrBadRequest(err.Error())
		}
		if target[0] != org {
			return zip.ErrForbidden("path is outside the caller's organization")
		}
		grants := make([]authz.Grant, 0, len(req.Grants))
		for _, g := range req.Grants {
			scope, err := authz.ParsePath(g.Scope)
			if err != nil {
				return zip.ErrBadRequest(err.Error())
			}
			if scope[0] != org {
				return zip.ErrForbidden("grant scope is outside the caller's organization")
			}
			grants = append(grants, authz.Grant{
				Subject: g.Subject,
				Scope:   scope,
				Role:    authz.Role(g.Role),
				Expiry:  g.Expiry,
			})
		}
		return c.JSON(http.StatusOK, map[string]any{
			"allow":   authz.Can(req.Subject, authz.Verb(req.Verb), target, grants),
			"subject": req.Subject,
			"verb":    req.Verb,
			"path":    target.String(),
		})
	})

	logger.Info("authz mounted")
	return nil
}

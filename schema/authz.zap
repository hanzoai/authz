# Hanzo authz — ZAP Schema
#
# Server: authz (Go) at authz.hanzo.svc.cluster.local or via the unified
# cloud binary at api.hanzo.ai/v1/authz.
#
# This schema is the minimum ZAP-typed public surface needed for the
# HIP-0106 Mount() contract. The full enforcement library remains
# importable directly (package casbin at module root) for in-process
# consumers that need richer semantics than the HTTP surface exposes.
# Wider ZAP-typed handlers (BatchCheck, AddPolicies, …) will land as
# separate schema PRs.
#
# Code generation:
#   zapc generate schema/authz.zap --lang go   --out ./gen/zap/
#   zapc generate schema/authz.zap --lang ts   --out ./gen/zap/

# ── Health ────────────────────────────────────────────────────────────────

struct HealthRequest
  # No fields. Probe is a side-effect-free GET.

struct HealthResponse
  status   Text
  service  Text

# ── Check ────────────────────────────────────────────────────────────────

struct CheckRequest
  sub  Text
  obj  Text
  act  Text

struct CheckResponse
  allow  Bool
  sub    Text
  obj    Text
  act    Text

# ── Service interface ────────────────────────────────────────────────────

interface AuthzService
  # Liveness probe. Always answers ok unless the process is unreachable.
  # Mounted at GET /v1/authz/health by Mount(app, deps).
  health (request HealthRequest) -> (response HealthResponse)

  # Policy check for the org identified by the gateway-minted X-Org-Id.
  # Returns allow=true iff the (sub, obj, act) triple is permitted by
  # the per-org policy store. Mounted at POST /v1/authz/check.
  check (request CheckRequest) -> (response CheckResponse)

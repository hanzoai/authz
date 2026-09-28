# authz

**Org:** hanzoai  ·  **Ecosystem:** hanzo  ·  **Path:** `/Users/a/work/hanzo/hanzoai/authz`
**Origin:** https://github.com/hanzoai/authz.git

## Discovery

This file (`LLM.md`) is the canonical agent-facing readme, and the one that is committed; `CLAUDE.md`, `AGENTS.md` and `GEMINI.md` are local symlinks to it.

## Where to look first

- `README.md` — human-facing overview (if present)
- `package.json` / `Cargo.toml` / `pyproject.toml` / `go.mod` — language & deps
- `.github/workflows/` — CI surface
- `docs/` — extended docs (if present)

## Sibling repos

See the org-level `LLM.md` at `/Users/a/work/hanzo/hanzoai/LLM.md` for the full inventory of sibling repos and inter-repo dependencies.

## SuperAdmin — one rule

`Claims.Sudo` is SuperAdmin: a person (`!Machine()`) whose own org, `Home()` —
the first entry of `orgs`, which IAM opens with the org its user row lives in —
is `AdminOrg`. IAM decides the same rule on the row (`schema.User.SuperAdmin`),
so a token reads the way the row it was minted from reads.

A membership of `admin` held from a brand org confers nothing: not `Sudo`, not
an `EffectiveOrg` switch into it, not `OrgAdmin`, not a `Grants` path, not
`Principal.MemberOf`/`AdminOf`. Every other membership is unchanged. The `owner`
claim is the minting application's org and never decides authority;
`Claims.Principal` projects a person onto `Home()`.

`testdata/claims.json` states the predicates as data; hanzoai/datastore embeds
it, so the two readers cannot drift without a suite going red.

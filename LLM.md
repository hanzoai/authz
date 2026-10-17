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

## Directories — every customer's home, no one's tenant

Each brand keeps its customers' accounts in one org of its own: `DirectoryOf`
maps `hanzo`→`hanzo-id`, `lux`→`lux-id`, `zoo`→`zoo-id`, `pars`→`pars-id`. A
directory holds identities and nothing else. It is held (no customer founds
one) and the platform's (`IsPlatformOrg`), and it opens to nobody: a membership
of it is not an `EffectiveOrg` switch, not `OrgAdmin`, not a `Grants` path, and
`Principal.MemberOf`/`AdminOf`/`OwnerOf` refuse it to everyone but a SuperAdmin,
so living there reaches none of the other customers in it. A customer's own row
stays readable (the self-read clause names the row, not the org).

`Home()` stays the identity: for a customer it is the directory, and
`<Home>/<username>` is who they are. What a request acts in when it selects
nothing is `Default()`: the home, or for a directory home the first org the
membership set opens — the personal org, which IAM lists right after the home.
An account whose set opens nothing has no default, and every org gate fails
closed. `EffectiveOrg` and `LedgerOrg` fall back to `Default()`. `Tenancy()` is
the opened part of the set, in order (its first entry is `Default()`): what a
surface offers as a choice of org, and what IAM's `groups` claim carries.

An org the platform runs (`IsPlatformOrg`: the reserved orgs, the brands, the
platform's own names, the directories) opens to the people who run it — its
owners and admins — to its own machines, and to a SuperAdmin: `opens` refuses a plain member's
membership there, `Default()` skips it, and `Principal.MemberOf` refuses a plain
person (its own machines and the application serving it are unchanged). A
customer who landed in a brand org is not one tenant with its staff, so they act
in no org of the platform's; with no org of their own they act in none.

`IsHeldOrg` is still the founding rule: the platform's names, the orgs funded by
name (`adnexus`, `bootnode`, `osage`) and the directories. The funded orgs are
customers' orgs, so `IsPlatformOrg` leaves them out: a surface that treats the
platform's own orgs specially (KMS listing) asks that, not `IsHeldOrg`.

## Org roles

`owner > admin > member`, each scoped to one org. `Principal.AdminOf` is owner
or admin (and an org admin of the home org); `Principal.OwnerOf` is the owner
role alone, or a SuperAdmin. Only `OwnerOf` deletes an org or grants, removes,
demotes or transfers the owner role; an admin runs members and admins. The admin
org is owned by the SuperAdmins alone, and a machine owns nothing.

`testdata/claims.json` states the predicates as data; hanzoai/datastore embeds
it, so the two readers cannot drift without a suite going red.

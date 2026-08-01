# Hanzo Authz

The access-control library every Hanzo Go service uses to read a token and decide whether
a caller may do a thing: JWT verification, claims, and the grant calculus over
organizations, apps and paths.

## Install

```bash
go get github.com/hanzoai/authz
```

## Use it

Verify a token — this is the same library IAM signs with, so a reader here cannot disagree
with the issuer about what was signed:

```go
claims, err := authz.Verify(token, keys, []string{"https://hanzo.id"})
```

`keys` is a `func(kid string) []crypto.PublicKey`. Key material is an **input**: fetching
and caching a JWKS is I/O, and this package does none — the edge owns the fetch and hands
the result in. A nil `Keys`, or one that resolves nothing, verifies nothing.

From there, `Claims` carries the caller's identity, org memberships and app grants;
`ParsePath` and `VerbOf` turn a request into the pair the grant calculus decides on.
`IsAPIKey` distinguishes an `hk-` key from a JWT.

Only the algorithms IAM's signer produces are accepted — RSA and EC, plus ML-DSA-65 for a
post-quantum certificate. `none` and HMAC are rejected.

## Docs

[`LLM.md`](LLM.md) for the layout. The `edge/` and `serve/` packages hold the pieces that
do need I/O — key fetching and the HTTP surface — kept out of the leaf on purpose.

## License

See [LICENSE](LICENSE).

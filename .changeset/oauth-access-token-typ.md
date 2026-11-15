---
"@better-auth/oauth-provider": minor
"@better-auth/mcp": minor
---

The OAuth provider now accepts a JWT as an access token only when its header has `typ: at+jwt` (RFC 9068 §4). Before, any JWT signed with the provider's keys that carried `azp`, such as one app code signed with `auth.api.signJWT`, passed at introspection, revocation, UserInfo, token exchange, and `verifyResourceRequest`.

`oauthProviderResourceClient` now defaults `verifyOptions.typ` to `at+jwt`, and `requireMcpAuth` requires it, so both reject other JWTs with `401 invalid_token`. Pass `verifyOptions.typ` to the resource client to accept another issuer's value.

**Breaking for custom signers:** a custom `jwt.sign` in the JWT plugin must apply its `header` argument, which carries `typ: at+jwt`. Access tokens from a signer that drops it are now inactive. The provider logs a warning at startup when `jwt.sign` is set.

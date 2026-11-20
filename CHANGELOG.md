# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-20

### Added

- `Strategy` for "Sign in with Hytale", using the OpenID Connect authorization
  code flow with PKCE (`S256`) and `state`.
- HTTP Basic client authentication for confidential clients, and support for
  public clients.
- ID token validation: RS256 signature against the issuer's JSON Web Key Set,
  `iss`, `aud`, `azp`, `exp`, `nbf` and `at_hash`.
- Profile built from Hytale claims for the `hytale:profile` and `account:*`
  scopes.
- `Strategy#userProfile()` to read current claims from the UserInfo endpoint.
- Compatibility with `passport-oauth2-refresh`.
- TypeScript definitions.

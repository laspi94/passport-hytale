# passport-hytale

[Passport](https://www.passportjs.org/) strategy for authenticating with
"Sign in with Hytale" using OpenID Connect.

This module lets you identify Hytale players in your Node.js applications
without handling their credentials. By plugging into Passport, Sign in with
Hytale can be integrated into any application or framework that supports
[Connect](https://github.com/senchalabs/connect#readme)-style middleware,
including [Express](https://expressjs.com/).

> This is an unofficial, community-maintained package. It is not affiliated
> with or endorsed by Hypixel Studios.

## Install

```sh
$ npm install passport-hytale
```

Requires Node.js 20 or later. TypeScript definitions are included.

## Usage

#### Register an application

Sign-in needs an OAuth client issued by Hytale. There is no self-service
registration: in your Hytale account, open **Creators & Developers → Developer
Apps** and apply for a client. Staff review each application. Once it is
approved you receive a client ID and, for confidential clients, a one-time
client secret.

- **Confidential** clients are server-side applications that can keep a
  secret. Configure the strategy with `clientSecret`.
- **Public** clients are native or browser-only applications that cannot.
  Leave `clientSecret` out.

Redirect URIs must be absolute `https` URLs (`http` is allowed only for
`localhost` and `127.0.0.1`), with no fragment and no wildcard. Register the
URL you pass as `callbackURL`.

#### Configure strategy

```js
var HytaleStrategy = require('passport-hytale');

passport.use(new HytaleStrategy({
    clientID: process.env.HYTALE_CLIENT_ID,
    clientSecret: process.env.HYTALE_CLIENT_SECRET,
    callbackURL: 'https://www.example.com/oauth2/redirect/hytale',
    scope: [ 'hytale:profile' ]
  },
  function verify(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ hytaleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
```

Identify players by `profile.id` (the `sub` claim). It is stable for your
application and does not change when the player switches game profiles. The
same player gets a different `profile.id` in every application.

#### Define routes

```js
app.get('/login/hytale', passport.authenticate('hytale'));

app.get('/oauth2/redirect/hytale',
  passport.authenticate('hytale', { failureRedirect: '/login', failureMessage: true }),
  function(req, res) {
    res.redirect('/');
  });
```

The strategy keeps the `state` and the PKCE code verifier in the session
between the redirect and the callback, so session middleware such as
[`express-session`](https://github.com/expressjs/session) must run before
Passport.

Application state can be passed as an object and is available as
`req.authInfo.state` after the callback:

```js
app.get('/login/hytale', passport.authenticate('hytale', { state: { returnTo: '/play' } }));
```

## Scopes

`openid` is always requested. Request only the scopes granted to your client:
scope matching is exact, and anything else is rejected with `invalid_scope`.

| Scope                      | Profile                                                       |
|----------------------------|---------------------------------------------------------------|
| `openid`                   | `id`                                                          |
| `hytale:profile`           | `gameProfile` (`{ uuid, username }`), `username`, `displayName` |
| `account:shared_source`    | `sharedSource` (boolean)                                      |
| `account:game_ownership`   | `gameOwnership` (boolean)                                     |
| `account:parental_managed` | `parentalManaged` (boolean)                                   |
| `offline`                  | a refresh token (see [Refresh tokens](#refresh-tokens))       |

With `hytale:profile`, players pick a game profile at sign-in, and they can
pick a different one each time. Unlike `profile.id`, `gameProfile.uuid` is a
real, public game identity that is the same in every application the player
shares it with.

Scopes can also be set for a single request:

```js
passport.authenticate('hytale', { scope: [ 'hytale:profile', 'account:shared_source' ] });
```

## Profile

The profile passed to the verify callback is built from the ID token:

| Property          | Description                                                           |
|-------------------|-----------------------------------------------------------------------|
| `provider`        | Always `'hytale'`.                                                    |
| `id`              | Stable, per-application anonymous identifier (`sub`).                 |
| `displayName`     | Game profile username, or an empty string without `hytale:profile`.   |
| `username`        | Game profile username.                                                |
| `gameProfile`     | `{ uuid, username }` of the game profile picked at sign-in.           |
| `sharedSource`    | Whether the account has Shared Source access.                         |
| `gameOwnership`   | Whether the account owns Hytale.                                      |
| `parentalManaged` | Whether the account is parentally managed.                            |
| `_json`           | All claims, including `auth_time`, `sid`, `jti` and `at_hash`.        |
| `_raw`            | The claims as JSON text.                                              |

Properties for scopes that were not granted are left out. Hytale never
provides an email address or account ID.

## Security

- Authorization always uses the authorization code flow with PKCE (`S256`) and
  `state`. Hytale requires PKCE from every client, confidential ones included.
- Confidential clients authenticate to the token endpoint with HTTP Basic
  (`client_secret_basic`). The secret is never sent in the request body,
  which Hytale rejects. Public clients send only their `client_id`.
- The ID token is validated before it is used: its RS256 signature against
  Hytale's JSON Web Key Set (cached, and re-fetched when the keys rotate),
  `iss`, `aud`, `azp`, `exp`, `nbf` and `at_hash`. No request is made to the
  UserInfo endpoint during sign-in.
- Access tokens are opaque and last one hour. Do not parse them.

## Errors

- A player who declines consent (`access_denied`), an invalid ID token, or a
  `state` mismatch makes authentication fail, which honors `failureRedirect`
  and `failureMessage`.
- Other authorization errors (such as `invalid_scope`) are passed to `next()`
  as an `AuthorizationError`. Token endpoint errors (such as `invalid_grant`
  for an expired or reused code) are passed as a `TokenError`, and network
  or HTTP failures as an `InternalOAuthError`. These classes are exported by
  [`passport-oauth2`](https://github.com/jaredhanson/passport-oauth2).

## Refresh tokens

Refresh tokens are opt-in. Enable them for your client in the developer portal
and request the `offline` scope. If the player allows it, the verify callback
receives a refresh token that is valid for 30 days. Otherwise `refreshToken`
is `undefined`.

Each use of a refresh token rotates it. Store the new one and discard the old
one: reusing a refresh token revokes the whole chain. The strategy works with
[`passport-oauth2-refresh`](https://github.com/fiznool/passport-oauth2-refresh):

```js
var refresh = require('passport-oauth2-refresh');

var strategy = new HytaleStrategy({ /* ... */ }, verify);
passport.use(strategy);
refresh.use(strategy);

refresh.requestNewAccessToken('hytale', user.refreshToken, function(err, accessToken, refreshToken) {
  if (err) { return next(err); }
  // Save the rotated `refreshToken`, then read the current claims.
  strategy.userProfile(accessToken, function(err, profile) {
    // profile.sharedSource reflects the account's current state.
  });
});
```

Claims are recomputed on every refresh, so this is how an application checks
whether a player still has Shared Source access. If the game profile granted
through `hytale:profile` no longer exists, the refresh is denied and the
player must sign in again. Revoke refresh tokens you no longer need at
`https://connect.accounts.hytale.com/oauth2/revoke`.

## TypeScript

```ts
import passport from 'passport';
import HytaleStrategy from 'passport-hytale';

passport.use(new HytaleStrategy({
  clientID: process.env.HYTALE_CLIENT_ID!,
  clientSecret: process.env.HYTALE_CLIENT_SECRET,
  callbackURL: 'https://www.example.com/oauth2/redirect/hytale',
  scope: ['hytale:profile'],
}, (accessToken, refreshToken, profile, done) => {
  // profile is a HytaleStrategy.Profile
  done(null, { id: profile.id, username: profile.username });
}));
```

`import { Strategy } from 'passport-hytale'` and
`import HytaleStrategy = require('passport-hytale')` work as well.

Parameter types are inferred for the verify callback above, and for its
`passReqToCallback: true` form. To also receive the token response, annotate
the parameters:

```ts
import HytaleStrategy, { type Profile, type TokenResponse, type VerifyCallback } from 'passport-hytale';

new HytaleStrategy(options, (
  accessToken: string,
  refreshToken: string | undefined,
  params: TokenResponse,
  profile: Profile,
  done: VerifyCallback,
) => {
  // params.id_token, params.expires_in, ...
});
```

## Options

| Option              | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `clientID`          | **Required.** Client ID issued by Hytale.                                   |
| `clientSecret`      | Client secret, for confidential clients. Omit it for public clients.        |
| `callbackURL`       | Registered redirect URI. A relative URL is resolved against the request.    |
| `scope`             | Array or space-separated string of scopes. `openid` is always added.        |
| `passReqToCallback` | When `true`, `req` is the first argument to the verify callback.            |
| `clockTolerance`    | Seconds of clock skew allowed when checking the ID token. Default: `0`.     |
| `store`             | Custom state store. It must persist the PKCE code verifier.                 |
| `sessionKey`        | Session key for the state. Default: `'oauth2:connect.accounts.hytale.com'`. |
| `proxy`             | Trust `X-Forwarded-*` headers when resolving a relative `callbackURL`.      |
| `issuer`            | Default: `'https://connect.accounts.hytale.com'`. Endpoints derive from it. |
| `authorizationURL`, `tokenURL`, `userInfoURL`, `jwksURL` | Override individual endpoints.                   |

## Example

The [example](example/) directory has a minimal Express application. Set
`HYTALE_CLIENT_ID` (and `HYTALE_CLIENT_SECRET` for a confidential client),
register `http://localhost:3000/oauth2/redirect/hytale` as a redirect URI,
then run:

```sh
$ cd example
$ npm install
$ npm start
```

## Development

```sh
$ npm test             # unit and integration tests
$ npm run test:types   # TypeScript definitions
$ npm run coverage     # tests with a coverage report
```

The tests run against a local fake provider that signs real RS256 ID tokens.

## License

[The MIT License](LICENSE)

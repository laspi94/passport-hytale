// Load modules.
var OAuth2Strategy = require('passport-oauth2')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError
  , querystring = require('querystring')
  , util = require('util')
  , Profile = require('./profile')
  , KeySet = require('./jwks')
  , idToken = require('./idtoken');


/**
 * Issuer of "Sign in with Hytale".
 */
var ISSUER = 'https://connect.accounts.hytale.com';


/**
 * Creates an instance of `Strategy`.
 *
 * "Sign in with Hytale" is OpenID Connect on a dedicated issuer.  This strategy
 * runs the authorization code flow, which is the only flow Hytale supports.
 * PKCE (`S256`) and `state` are always used, because Hytale requires both from
 * every client, confidential or public.
 *
 * The user profile is built from the claims in the ID token returned by the
 * token endpoint.  The ID token is validated before it is used: its RS256
 * signature is checked against the issuer's JSON Web Key Set, and its `iss`,
 * `aud`, `exp` and (when present) `azp` and `at_hash` claims are checked.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, cb) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `cb` with the following arguments:
 *
 *     cb(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - `clientID`          client identifier issued by Hytale
 *   - `clientSecret`      client secret, for confidential clients only; omit it for public clients
 *   - `callbackURL`       URL to which Hytale will redirect the user after authorization
 *   - `scope`             scopes to request; `openid` is always included
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *   - `clockTolerance`    seconds of clock skew allowed when checking `exp` (default: `0`)
 *
 * Examples:
 *
 *     passport.use(new HytaleStrategy({
 *         clientID: process.env.HYTALE_CLIENT_ID,
 *         clientSecret: process.env.HYTALE_CLIENT_SECRET,
 *         callbackURL: 'https://www.example.net/auth/hytale/callback',
 *         scope: [ 'openid', 'hytale:profile' ]
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate({ hytaleId: profile.id }, function (err, user) {
 *           return cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (typeof verify != 'function') { throw new TypeError('HytaleStrategy requires a verify callback'); }
  if (!options.clientID) { throw new TypeError('HytaleStrategy requires a clientID option'); }
  if (options.store && typeof options.store == 'object'
      && (typeof options.store.store != 'function' || options.store.store.length != 5)) {
    // PKCE is mandatory, so the code verifier has to be persisted between the
    // authorization request and the callback.
    throw new TypeError('HytaleStrategy requires a state store that persists the PKCE code verifier: store(req, verifier, state, meta, callback)');
  }

  var issuer = (options.issuer || ISSUER).replace(/\/+$/, '');

  var opts = Object.assign({}, options);
  opts.authorizationURL = options.authorizationURL || issuer + '/oauth2/auth';
  opts.tokenURL = options.tokenURL || issuer + '/oauth2/token';
  opts.scope = normalizeScope(options.scope);
  opts.scopeSeparator = ' ';
  opts.state = true;
  opts.pkce = 'S256';
  // The profile comes from the validated ID token rather than from a request
  // to the UserInfo endpoint.
  opts.skipUserProfile = true;

  var self = this;

  function verified(req, accessToken, refreshToken, params, done) {
    self._loadIdTokenProfile(accessToken, params, function(err, profile, info) {
      if (err) { return done(err); }
      if (!profile) { return done(null, false, info); }

      try {
        if (options.passReqToCallback) {
          if (verify.length == 6) {
            verify(req, accessToken, refreshToken, params, profile, done);
          } else { // arity == 5
            verify(req, accessToken, refreshToken, profile, done);
          }
        } else {
          if (verify.length == 5) {
            verify(accessToken, refreshToken, params, profile, done);
          } else { // arity == 4
            verify(accessToken, refreshToken, profile, done);
          }
        }
      } catch (ex) {
        return done(ex);
      }
    });
  }

  // `passport-oauth2` dispatches on the arity of the verify function.  These
  // wrappers always ask for the token response (`params`), which carries the
  // ID token, and then call the application's verify function with the arity
  // it declared.
  var wrapped = options.passReqToCallback
    ? function(req, accessToken, refreshToken, params, profile, done) {
        verified(req, accessToken, refreshToken, params, done);
      }
    : function(accessToken, refreshToken, params, profile, done) {
        verified(undefined, accessToken, refreshToken, params, done);
      };

  OAuth2Strategy.call(this, opts, wrapped);
  this.name = 'hytale';
  this._issuer = issuer;
  this._userInfoURL = options.userInfoURL || issuer + '/userinfo';
  this._clockTolerance = options.clockTolerance || 0;

  this._oauth2.useAuthorizationHeaderforGET(true);
  this._oauth2.getOAuthAccessToken = getOAuthAccessToken;

  var oauth2 = this._oauth2;
  this._keys = new KeySet({
    url: options.jwksURL || issuer + '/.well-known/jwks.json',
    fetch: function(url, cb) {
      oauth2._request('GET', url, { 'Accept': 'application/json' }, '', null, function(err, body) {
        if (err) { return cb(new InternalOAuthError('Failed to fetch JSON Web Key Set', err)); }
        cb(null, body);
      });
    }
  });
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);


/**
 * Authenticate request by delegating to Hytale.
 *
 * @param {http.IncomingMessage} req
 * @param {object} [options]
 * @access protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};

  if (typeof options.state == 'string') {
    // `passport-oauth2` sends a string `state` as-is and skips the state
    // store, which would drop the PKCE code verifier.
    return this.error(new TypeError('HytaleStrategy manages the state parameter itself because PKCE is required; pass application state as an object instead of a string'));
  }
  if (options.scope) {
    options = Object.assign({}, options, { scope: normalizeScope(options.scope) });
  }

  OAuth2Strategy.prototype.authenticate.call(this, req, options);
};


/**
 * Retrieve user profile from Hytale's UserInfo endpoint.
 *
 * Sign-in does not call this method: the profile given to the verify callback
 * comes from the validated ID token.  Applications can call it with an access
 * token to read the account's current claims, for example after refreshing
 * tokens to check whether the user still has Shared Source access.
 *
 * @param {string} accessToken
 * @param {function} done
 * @access public
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get(this._userInfoURL, accessToken, function(err, body) {
    if (err) { return done(new InternalOAuthError('Failed to fetch user profile', err)); }

    var json;
    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }

    var profile = Profile.parse(json);
    profile.provider = 'hytale';
    profile._raw = body;
    profile._json = json;

    done(null, profile);
  });
};


/**
 * Validate the ID token in a token response and build a profile from it.
 *
 * @param {string} accessToken
 * @param {object} params
 * @param {function} done
 * @access private
 */
Strategy.prototype._loadIdTokenProfile = function(accessToken, params, done) {
  var token = params && params.id_token;
  if (!token) { return done(new Error('ID token not present in token response')); }

  idToken.verify(token, {
    issuer: this._issuer,
    audience: this._oauth2._clientId,
    keys: this._keys,
    clockTolerance: this._clockTolerance,
    accessToken: accessToken
  }, function(err, claims, info) {
    if (err) { return done(err); }
    if (!claims) { return done(null, false, info); }

    var profile = Profile.parse(claims);
    profile.provider = 'hytale';
    profile._raw = Buffer.from(token.split('.')[1], 'base64url').toString('utf8');
    profile._json = claims;

    done(null, profile);
  });
};


/**
 * Exchange an authorization code or a refresh token at the token endpoint.
 *
 * Replaces node-oauth's implementation, which always puts `client_secret` in
 * the request body.  Hytale rejects that: confidential clients authenticate
 * with HTTP Basic (`client_secret_basic`) and leave `client_id` out of the
 * body, while public clients send `client_id` and no secret.
 *
 * It is installed on the OAuth2 instance and relies on `this`, so that
 * `passport-oauth2-refresh`, which copies this function onto its own OAuth2
 * instance, refreshes tokens the same way.
 *
 * @param {string} code
 * @param {object} params
 * @param {function} callback
 * @this OAuth2
 * @access private
 */
function getOAuthAccessToken(code, params, callback) {
  params = Object.assign({}, params);
  var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
  params[codeParam] = code;
  delete params.client_secret;

  var headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
  };
  if (this._clientSecret) {
    delete params.client_id;
    // RFC 6749, section 2.3.1: the client identifier and secret are
    // form-encoded before being used as the Basic credentials.
    headers['Authorization'] = 'Basic ' + Buffer.from(formEncode(this._clientId) + ':' + formEncode(this._clientSecret)).toString('base64');
  } else {
    params.client_id = this._clientId;
  }

  this._request('POST', this._getAccessTokenUrl(), headers, querystring.stringify(params), null, function(err, body) {
    if (err) { return callback(err); }

    var results;
    try {
      results = JSON.parse(body);
    } catch (ex) {
      return callback(new Error('Failed to parse token response'));
    }

    var accessToken = results.access_token;
    var refreshToken = results.refresh_token;
    delete results.refresh_token;
    callback(null, accessToken, refreshToken, results);
  });
}

/**
 * Normalize requested scopes to an array that includes `openid`.
 *
 * @param {string|string[]} [scope]
 * @returns {string[]}
 * @access private
 */
function normalizeScope(scope) {
  var scopes = Array.isArray(scope) ? scope.slice() : (typeof scope == 'string' ? scope.split(/\s+/) : []);
  scopes = scopes.filter(function(s) { return !!s; });
  if (scopes.indexOf('openid') === -1) { scopes.unshift('openid'); }
  return scopes.filter(function(s, i) { return scopes.indexOf(s) === i; });
}

/**
 * Encode a value as `application/x-www-form-urlencoded`.
 *
 * @param {string} value
 * @returns {string}
 * @access private
 */
function formEncode(value) {
  return encodeURIComponent(value).replace(/%20/g, '+');
}


// Expose constructor.
module.exports = Strategy;

// A fake "Sign in with Hytale" provider for tests.
//
// It listens on a random local port, records every request it receives, and
// answers token, UserInfo and JSON Web Key Set requests with configurable
// handlers.  ID tokens are signed with a real RS256 key, so the strategy's
// validation runs exactly as it would against Hytale.

var http = require('http')
  , crypto = require('crypto')
  , querystring = require('querystring');


var CLIENT_ID = '7f0b8a4e-2c1d-4b8e-9a51-3d6f0c2e9b17';
var CLIENT_SECRET = 'cs-0123456789abcdefghijKLMNOP';
var SUBJECT = 'Xq3uZb8m1vR0kT9yWc2dLf5gHj7nPs4aBe6iOo1uYw0';
var GAME_PROFILE = { uuid: 'b1c3e8a2-5d4f-4e6a-9b7c-2f1d0e9a8c76', username: 'Kweebec' };


function Provider() {
  var pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  this.kid = 'test-key';
  this.privateKey = pair.privateKey;
  this.jwk = Object.assign(pair.publicKey.export({ format: 'jwk' }), { kid: this.kid, use: 'sig', alg: 'RS256' });
  this.requests = [];
  this.handlers = {};
  this.reset();
}

Provider.prototype.start = function(cb) {
  var self = this;
  this.server = http.createServer(function(req, res) {
    var chunks = [];
    req.on('data', function(chunk) { chunks.push(chunk); });
    req.on('end', function() {
      var body = Buffer.concat(chunks).toString('utf8');
      var record = {
        method: req.method,
        path: req.url.split('?')[0],
        url: req.url,
        headers: req.headers,
        body: body,
        form: querystring.parse(body)
      };
      self.requests.push(record);

      var handler = self.handlers[record.path];
      var out = handler ? handler.call(self, record) : { status: 404, body: { error: 'not_found' } };
      res.writeHead(out.status || 200, { 'Content-Type': 'application/json' });
      res.end(typeof out.body == 'string' ? out.body : JSON.stringify(out.body));
    });
  });
  this.server.listen(0, '127.0.0.1', function() {
    self.issuer = 'http://127.0.0.1:' + self.server.address().port;
    cb();
  });
};

Provider.prototype.stop = function(cb) {
  this.server.close(cb);
};

/**
 * Restore the default handlers and forget recorded requests.
 */
Provider.prototype.reset = function() {
  var self = this;
  this.requests = [];
  this.handlers = {
    '/oauth2/token': function() {
      return { body: self.tokenResponse() };
    },
    '/.well-known/jwks.json': function() {
      return { body: { keys: [ self.jwk ] } };
    },
    '/userinfo': function(req) {
      if (req.headers.authorization !== 'Bearer at-1') { return { status: 401, body: { error: 'invalid_token' } }; }
      return { body: { sub: SUBJECT, profile: GAME_PROFILE, shared_source: true } };
    }
  };
};

/**
 * Requests received on `path`.
 */
Provider.prototype.received = function(path) {
  return this.requests.filter(function(r) { return r.path === path; });
};

/**
 * Sign a JWT with the provider's key.
 */
Provider.prototype.sign = function(claims, header) {
  header = Object.assign({ alg: 'RS256', typ: 'JWT', kid: this.kid }, header);
  var input = b64(JSON.stringify(header)) + '.' + b64(JSON.stringify(claims));
  var signature = crypto.sign('RSA-SHA256', Buffer.from(input), this.privateKey).toString('base64url');
  return input + '.' + signature;
};

/**
 * Claims of a valid ID token for `accessToken`, merged with `overrides`.
 * Overrides set to `undefined` remove the claim.
 */
Provider.prototype.claims = function(overrides, accessToken) {
  var now = Math.floor(Date.now() / 1000);
  var claims = {
    iss: this.issuer,
    sub: SUBJECT,
    aud: [ CLIENT_ID ],
    exp: now + 3600,
    iat: now,
    auth_time: now,
    sid: 'sid-1',
    jti: 'jti-1',
    at_hash: atHash(accessToken || 'at-1'),
    profile: GAME_PROFILE,
    shared_source: true,
    game_ownership: true,
    parental_managed: false
  };
  Object.keys(overrides || {}).forEach(function(key) {
    if (overrides[key] === undefined) { delete claims[key]; } else { claims[key] = overrides[key]; }
  });
  return claims;
};

/**
 * A successful token response.
 */
Provider.prototype.tokenResponse = function(overrides) {
  return Object.assign({
    access_token: 'at-1',
    token_type: 'bearer',
    expires_in: 3599,
    scope: 'openid hytale:profile account:shared_source account:game_ownership account:parental_managed offline',
    refresh_token: 'rt-1',
    id_token: this.sign(this.claims())
  }, overrides);
};


function b64(text) {
  return Buffer.from(text).toString('base64url');
}

function atHash(accessToken) {
  var digest = crypto.createHash('sha256').update(accessToken).digest();
  return digest.subarray(0, 16).toString('base64url');
}


exports.Provider = Provider;
exports.CLIENT_ID = CLIENT_ID;
exports.CLIENT_SECRET = CLIENT_SECRET;
exports.SUBJECT = SUBJECT;
exports.GAME_PROFILE = GAME_PROFILE;

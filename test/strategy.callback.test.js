var crypto = require('crypto')
  , Strategy = require('../lib/strategy')
  , OAuth2Strategy = require('passport-oauth2')
  , support = require('./support/provider')
  , run = require('./support/run');


var CALLBACK_URL = 'https://www.example.net/auth/hytale/callback';
var SESSION_KEY = 'oauth2:127.0.0.1';


describe('Strategy callback', function() {

  var provider = new support.Provider();

  before(function(done) { provider.start(done); });
  after(function(done) { provider.stop(done); });
  beforeEach(function() { provider.reset(); });

  function createStrategy(options, verify) {
    return new Strategy(Object.assign({
      issuer: provider.issuer,
      clientID: support.CLIENT_ID,
      clientSecret: support.CLIENT_SECRET,
      callbackURL: CALLBACK_URL
    }, options), verify || function(accessToken, refreshToken, profile, cb) {
      return cb(null, { id: profile.id });
    });
  }

  function callbackRequest(state) {
    return function(req) {
      req.query = { code: 'code-1', state: 'handle-1' };
      req.session = {};
      req.session[SESSION_KEY] = { state: Object.assign({ handle: 'handle-1', code_verifier: 'verifier-1' }, state) };
    };
  }

  function tokenResponse(overrides) {
    provider.handlers['/oauth2/token'] = function() {
      return { body: provider.tokenResponse(overrides) };
    };
  }

  function idToken(claims, header) {
    tokenResponse({ id_token: provider.sign(provider.claims(claims), header) });
  }

  describe('for a confidential client', function() {
    var args, result, requests;

    before(async function() {
      provider.reset();
      var strategy = createStrategy({}, function(accessToken, refreshToken, profile, cb) {
        args = { accessToken: accessToken, refreshToken: refreshToken, profile: profile };
        return cb(null, { id: profile.id });
      });
      result = await run(strategy, callbackRequest());
      requests = provider.requests.slice();
    });

    function received(path) {
      return requests.filter(function(r) { return r.path === path; });
    }

    it('should succeed', function() {
      expect(result.type).to.equal('success');
      expect(result.user).to.deep.equal({ id: support.SUBJECT });
    });

    it('should authenticate to the token endpoint with HTTP Basic', function() {
      var request = received('/oauth2/token')[0];
      var credentials = Buffer.from(support.CLIENT_ID + ':' + support.CLIENT_SECRET).toString('base64');

      expect(request.method).to.equal('POST');
      expect(request.headers['authorization']).to.equal('Basic ' + credentials);
      expect(request.headers['content-type']).to.equal('application/x-www-form-urlencoded');
    });

    it('should send the code and code verifier without client_id or client_secret', function() {
      expect(received('/oauth2/token')[0].form).to.deep.equal({
        grant_type: 'authorization_code',
        code: 'code-1',
        redirect_uri: CALLBACK_URL,
        code_verifier: 'verifier-1'
      });
    });

    it('should pass the tokens to the verify callback', function() {
      expect(args.accessToken).to.equal('at-1');
      expect(args.refreshToken).to.equal('rt-1');
    });

    it('should build the profile from the ID token', function() {
      var profile = args.profile;

      expect(profile.provider).to.equal('hytale');
      expect(profile.id).to.equal(support.SUBJECT);
      expect(profile.username).to.equal('Kweebec');
      expect(profile.displayName).to.equal('Kweebec');
      expect(profile.gameProfile).to.deep.equal(support.GAME_PROFILE);
      expect(profile.sharedSource).to.equal(true);
      expect(profile.gameOwnership).to.equal(true);
      expect(profile.parentalManaged).to.equal(false);
      expect(profile._json.sub).to.equal(support.SUBJECT);
      expect(profile._json.iss).to.equal(provider.issuer);
      expect(JSON.parse(profile._raw)).to.deep.equal(profile._json);
    });

    it('should fetch the key set but not call the UserInfo endpoint', function() {
      expect(received('/.well-known/jwks.json')).to.have.length(1);
      expect(received('/userinfo')).to.have.length(0);
    });

    it('should consume the stored state', function() {
      expect(result.req.session[SESSION_KEY]).to.equal(undefined);
    });
  });

  describe('for a public client', function() {
    var result, request;

    before(async function() {
      provider.reset();
      result = await run(createStrategy({ clientSecret: undefined }), callbackRequest());
      request = provider.received('/oauth2/token')[0];
    });

    it('should succeed', function() {
      expect(result.type).to.equal('success');
    });

    it('should send client_id and the code verifier, without HTTP Basic', function() {

      expect(request.headers['authorization']).to.equal(undefined);
      expect(request.form).to.deep.equal({
        grant_type: 'authorization_code',
        code: 'code-1',
        redirect_uri: CALLBACK_URL,
        code_verifier: 'verifier-1',
        client_id: support.CLIENT_ID
      });
    });
  });

  describe('for a client secret with reserved characters', function() {
    it('should form-encode the HTTP Basic credentials', async function() {
      var result = await run(createStrategy({ clientSecret: 'a+b/c%d e' }), callbackRequest());
      var credentials = Buffer.from(support.CLIENT_ID + ':a%2Bb%2Fc%25d+e').toString('base64');

      expect(result.type).to.equal('success');
      expect(provider.received('/oauth2/token')[0].headers['authorization']).to.equal('Basic ' + credentials);
    });
  });

  describe('with a verify callback that accepts params', function() {
    it('should pass the token response', async function() {
      var params;
      var strategy = createStrategy({}, function(accessToken, refreshToken, p, profile, cb) {
        params = p;
        return cb(null, { id: profile.id });
      });

      var result = await run(strategy, callbackRequest());

      expect(result.type).to.equal('success');
      expect(params.access_token).to.equal('at-1');
      expect(params.token_type).to.equal('bearer');
      expect(params.expires_in).to.equal(3599);
      expect(params.id_token).to.be.a('string');
      expect(params).to.not.have.property('refresh_token');
    });
  });

  describe('with passReqToCallback', function() {
    it('should pass the request to a five-argument verify callback', async function() {
      var args;
      var strategy = createStrategy({ passReqToCallback: true }, function(req, accessToken, refreshToken, profile, cb) {
        args = { req: req, accessToken: accessToken, profile: profile };
        return cb(null, { id: profile.id });
      });

      var result = await run(strategy, callbackRequest());

      expect(result.type).to.equal('success');
      expect(args.req).to.equal(result.req);
      expect(args.accessToken).to.equal('at-1');
      expect(args.profile.id).to.equal(support.SUBJECT);
    });

    it('should pass the request and params to a six-argument verify callback', async function() {
      var args;
      var strategy = createStrategy({ passReqToCallback: true }, function(req, accessToken, refreshToken, params, profile, cb) {
        args = { req: req, params: params, profile: profile };
        return cb(null, { id: profile.id });
      });

      var result = await run(strategy, callbackRequest());

      expect(result.type).to.equal('success');
      expect(args.req).to.equal(result.req);
      expect(args.params.id_token).to.be.a('string');
      expect(args.profile.id).to.equal(support.SUBJECT);
    });
  });

  describe('without the offline scope', function() {
    it('should pass an undefined refresh token', async function() {
      var refreshToken = null;
      tokenResponse({ refresh_token: undefined });
      var strategy = createStrategy({}, function(accessToken, rt, profile, cb) {
        refreshToken = rt;
        return cb(null, { id: profile.id });
      });

      var result = await run(strategy, callbackRequest());

      expect(result.type).to.equal('success');
      expect(refreshToken).to.equal(undefined);
    });
  });

  describe('without optional claims', function() {
    it('should build a profile with only the subject', async function() {
      var profile;
      idToken({ profile: undefined, shared_source: undefined, game_ownership: undefined, parental_managed: undefined });
      var strategy = createStrategy({}, function(accessToken, refreshToken, p, cb) {
        profile = p;
        return cb(null, { id: p.id });
      });

      var result = await run(strategy, callbackRequest());

      expect(result.type).to.equal('success');
      expect(profile.id).to.equal(support.SUBJECT);
      expect(profile.displayName).to.equal('');
      expect(profile).to.not.have.any.keys('username', 'gameProfile', 'sharedSource', 'gameOwnership', 'parentalManaged');
    });
  });

  describe('with application state', function() {
    it('should pass it in info', async function() {
      var result = await run(createStrategy(), callbackRequest({ state: { returnTo: '/play' } }));

      expect(result.type).to.equal('success');
      expect(result.info).to.deep.equal({ state: { returnTo: '/play' } });
    });
  });

  describe('when the verify callback fails', function() {
    it('should fail with its info', async function() {
      var strategy = createStrategy({}, function(accessToken, refreshToken, profile, cb) {
        return cb(null, false, { message: 'Account suspended' });
      });

      var result = await run(strategy, callbackRequest());

      expect(result.type).to.equal('fail');
      expect(result.challenge).to.deep.equal({ message: 'Account suspended' });
    });
  });

  describe('when the verify callback throws', function() {
    it('should error', async function() {
      var strategy = createStrategy({}, function() {
        throw new Error('something went wrong');
      });

      var result = await run(strategy, callbackRequest());

      expect(result.type).to.equal('error');
      expect(result.err.message).to.equal('something went wrong');
    });
  });

  describe('when the user denies consent', function() {
    it('should fail without contacting the token endpoint', async function() {
      var result = await run(createStrategy(), function(req) {
        req.query = { error: 'access_denied', error_description: 'The resource owner denied the request.', state: 'handle-1' };
      });

      expect(result.type).to.equal('fail');
      expect(result.challenge).to.deep.equal({ message: 'The resource owner denied the request.' });
      expect(provider.received('/oauth2/token')).to.have.length(0);
    });
  });

  describe('when authorization fails for another reason', function() {
    it('should error with an AuthorizationError', async function() {
      var result = await run(createStrategy(), function(req) {
        req.query = { error: 'invalid_scope', error_description: 'The requested scope is invalid.', state: 'handle-1' };
      });

      expect(result.type).to.equal('error');
      expect(result.err).to.be.an.instanceof(OAuth2Strategy.AuthorizationError);
      expect(result.err.code).to.equal('invalid_scope');
      expect(result.err.message).to.equal('The requested scope is invalid.');
    });
  });

  describe('when the state does not match', function() {
    it('should fail with 403 without contacting the token endpoint', async function() {
      var result = await run(createStrategy(), function(req) {
        callbackRequest()(req);
        req.query.state = 'forged';
      });

      expect(result.type).to.equal('fail');
      expect(result.status).to.equal(403);
      expect(result.challenge).to.deep.equal({ message: 'Invalid authorization request state.' });
      expect(provider.received('/oauth2/token')).to.have.length(0);
    });
  });

  describe('when the token endpoint rejects the code', function() {
    it('should error with a TokenError', async function() {
      provider.handlers['/oauth2/token'] = function() {
        return { status: 400, body: { error: 'invalid_grant', error_description: 'The authorization code has expired.' } };
      };

      var result = await run(createStrategy(), callbackRequest());

      expect(result.type).to.equal('error');
      expect(result.err).to.be.an.instanceof(OAuth2Strategy.TokenError);
      expect(result.err.code).to.equal('invalid_grant');
      expect(result.err.message).to.equal('The authorization code has expired.');
    });
  });

  describe('when the token response is not JSON', function() {
    it('should error with an InternalOAuthError', async function() {
      provider.handlers['/oauth2/token'] = function() {
        return { body: 'access_token=at-1' };
      };

      var result = await run(createStrategy(), callbackRequest());

      expect(result.type).to.equal('error');
      expect(result.err).to.be.an.instanceof(OAuth2Strategy.InternalOAuthError);
      expect(result.err.message).to.equal('Failed to obtain access token');
      expect(result.err.oauthError.message).to.equal('Failed to parse token response');
    });
  });

  describe('when the token response has no ID token', function() {
    it('should error', async function() {
      tokenResponse({ id_token: undefined });

      var result = await run(createStrategy(), callbackRequest());

      expect(result.type).to.equal('error');
      expect(result.err.message).to.equal('ID token not present in token response');
    });
  });

  describe('when the key set cannot be fetched', function() {
    it('should error with an InternalOAuthError', async function() {
      provider.handlers['/.well-known/jwks.json'] = function() {
        return { status: 503, body: { error: 'unavailable' } };
      };

      var result = await run(createStrategy(), callbackRequest());

      expect(result.type).to.equal('error');
      expect(result.err).to.be.an.instanceof(OAuth2Strategy.InternalOAuthError);
      expect(result.err.message).to.equal('Failed to fetch JSON Web Key Set');
      expect(result.err.oauthError.statusCode).to.equal(503);
    });
  });

  describe('with an invalid ID token', function() {
    var verifyCalled;

    beforeEach(function() { verifyCalled = false; });

    async function expectFailure(message, options) {
      var strategy = createStrategy(options, function(accessToken, refreshToken, profile, cb) {
        verifyCalled = true;
        return cb(null, { id: profile.id });
      });

      var result = await run(strategy, callbackRequest());

      expect(result.type).to.equal('fail');
      expect(result.challenge).to.deep.equal({ message: message });
      expect(verifyCalled).to.equal(false);
    }

    it('should fail when it was issued by another issuer', async function() {
      idToken({ iss: 'https://connect.example.test' });
      await expectFailure('ID token not issued by expected OpenID provider');
    });

    it('should fail when it was issued to another client', async function() {
      idToken({ aud: [ 'another-client' ] });
      await expectFailure('ID token not intended for this client');
    });

    it('should fail when it was authorized for another client', async function() {
      idToken({ aud: [ support.CLIENT_ID, 'another-client' ], azp: 'another-client' });
      await expectFailure('ID token not authorized for this client');
    });

    it('should fail when it has expired', async function() {
      idToken({ exp: Math.floor(Date.now() / 1000) - 120 });
      await expectFailure('ID token has expired');
    });

    it('should fail when it is not valid yet', async function() {
      idToken({ nbf: Math.floor(Date.now() / 1000) + 120 });
      await expectFailure('ID token is not yet valid');
    });

    it('should fail when it was issued with another access token', async function() {
      tokenResponse({ access_token: 'at-2' });
      await expectFailure('Access token does not match the ID token');
    });

    it('should fail when its signature does not verify', async function() {
      var token = provider.sign(provider.claims());
      var tampered = token.split('.');
      tampered[1] = Buffer.from(JSON.stringify(provider.claims({ sub: 'someone-else' }))).toString('base64url');
      tokenResponse({ id_token: tampered.join('.') });
      await expectFailure('Invalid ID token signature');
    });

    it('should fail when it is signed by an unknown key', async function() {
      idToken({}, { kid: 'unknown-key' });
      await expectFailure('No signing key matches the ID token');
    });

    it('should fail when it is not signed with RS256', async function() {
      var header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
      var payload = Buffer.from(JSON.stringify(provider.claims())).toString('base64url');
      tokenResponse({ id_token: header + '.' + payload + '.' });
      await expectFailure('Unexpected ID token signing algorithm: none');
    });

    it('should fail when it is malformed', async function() {
      tokenResponse({ id_token: 'not-a-jwt' });
      await expectFailure('Malformed ID token');
    });

    it('should accept an expired token within the clock tolerance', async function() {
      idToken({ exp: Math.floor(Date.now() / 1000) - 30 });

      var result = await run(createStrategy({ clockTolerance: 60 }), callbackRequest());

      expect(result.type).to.equal('success');
    });
  });

  describe('signing in twice', function() {
    it('should fetch the key set once', async function() {
      var strategy = createStrategy();

      var first = await run(strategy, callbackRequest());
      var second = await run(strategy, callbackRequest());

      expect(first.type).to.equal('success');
      expect(second.type).to.equal('success');
      expect(provider.received('/oauth2/token')).to.have.length(2);
      expect(provider.received('/.well-known/jwks.json')).to.have.length(1);
    });
  });

  describe('after the issuer rotates its keys', function() {
    var original;

    before(function() {
      original = { privateKey: provider.privateKey, kid: provider.kid, jwk: provider.jwk };
    });

    after(function() {
      Object.assign(provider, original);
    });

    it('should fetch the key set again', async function() {
      var strategy = createStrategy();
      strategy._keys._cooldown = 0;

      var first = await run(strategy, callbackRequest());

      var rotated = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      provider.privateKey = rotated.privateKey;
      provider.kid = 'rotated-key';
      provider.jwk = Object.assign(rotated.publicKey.export({ format: 'jwk' }), { kid: 'rotated-key', use: 'sig', alg: 'RS256' });

      var second = await run(strategy, callbackRequest());

      expect(first.type).to.equal('success');
      expect(second.type).to.equal('success');
      expect(provider.received('/.well-known/jwks.json')).to.have.length(2);
    });
  });

});

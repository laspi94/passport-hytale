var crypto = require('crypto')
  , Strategy = require('../lib/strategy')
  , run = require('./support/run');


var CALLBACK_URL = 'https://www.example.net/auth/hytale/callback';
var SESSION_KEY = 'oauth2:connect.accounts.hytale.com';


describe('Strategy authorization request', function() {

  function withSession(req) {
    req.session = {};
  }

  describe('with default options', function() {
    var strategy = new Strategy({
      clientID: 'ABC123',
      clientSecret: 'secret',
      callbackURL: CALLBACK_URL
    }, function() {});

    var result, location;

    before(async function() {
      result = await run(strategy, withSession);
      location = new URL(result.location);
    });

    it('should redirect to the authorization endpoint', function() {
      expect(result.type).to.equal('redirect');
      expect(location.origin + location.pathname).to.equal('https://connect.accounts.hytale.com/oauth2/auth');
    });

    it('should request an authorization code', function() {
      expect(location.searchParams.get('response_type')).to.equal('code');
      expect(location.searchParams.get('client_id')).to.equal('ABC123');
      expect(location.searchParams.get('redirect_uri')).to.equal(CALLBACK_URL);
    });

    it('should request the openid scope', function() {
      expect(location.searchParams.get('scope')).to.equal('openid');
    });

    it('should not send the client secret', function() {
      expect(result.location).to.not.include('secret');
    });

    it('should send an S256 code challenge for the stored code verifier', function() {
      var stored = result.req.session[SESSION_KEY].state;
      var challenge = crypto.createHash('sha256').update(stored.code_verifier).digest('base64url');

      expect(stored.code_verifier).to.match(/^[A-Za-z0-9_-]{43}$/);
      expect(location.searchParams.get('code_challenge_method')).to.equal('S256');
      expect(location.searchParams.get('code_challenge')).to.equal(challenge);
    });

    it('should send the stored state', function() {
      var stored = result.req.session[SESSION_KEY].state;

      expect(stored.handle).to.be.a('string').with.length.above(0);
      expect(location.searchParams.get('state')).to.equal(stored.handle);
    });
  });

  describe('with scopes from the constructor', function() {
    var strategy = new Strategy({
      clientID: 'ABC123',
      callbackURL: CALLBACK_URL,
      scope: [ 'hytale:profile', 'account:shared_source' ]
    }, function() {});

    it('should request openid and the given scopes, space-separated', async function() {
      var result = await run(strategy, withSession);
      expect(new URL(result.location).searchParams.get('scope')).to.equal('openid hytale:profile account:shared_source');
    });
  });

  describe('with scopes from authenticate options', function() {
    var strategy = new Strategy({
      clientID: 'ABC123',
      callbackURL: CALLBACK_URL,
      scope: [ 'hytale:profile' ]
    }, function() {});

    it('should request openid and the given scopes', async function() {
      var result = await run(strategy, withSession, { scope: 'offline hytale:profile' });
      expect(new URL(result.location).searchParams.get('scope')).to.equal('openid offline hytale:profile');
    });
  });

  describe('with a relative callback URL', function() {
    var strategy = new Strategy({
      clientID: 'ABC123',
      callbackURL: '/auth/hytale/callback'
    }, function() {});

    it('should resolve it against the request URL', async function() {
      var result = await run(strategy, function(req) {
        req.session = {};
        req.url = '/auth/hytale';
        req.headers.host = 'www.example.net';
        req.connection = { encrypted: true };
      });
      expect(new URL(result.location).searchParams.get('redirect_uri')).to.equal(CALLBACK_URL);
    });
  });

  describe('with application state', function() {
    var strategy = new Strategy({
      clientID: 'ABC123',
      callbackURL: CALLBACK_URL
    }, function() {});

    it('should store it in the session next to the code verifier', async function() {
      var result = await run(strategy, withSession, { state: { returnTo: '/play' } });
      var stored = result.req.session[SESSION_KEY].state;

      expect(stored.state).to.deep.equal({ returnTo: '/play' });
      expect(stored.code_verifier).to.be.a('string');
      expect(new URL(result.location).searchParams.get('state')).to.equal(stored.handle);
    });
  });

  describe('with a state string', function() {
    var strategy = new Strategy({
      clientID: 'ABC123',
      callbackURL: CALLBACK_URL
    }, function() {});

    it('should error, because the code verifier would not be stored', async function() {
      var result = await run(strategy, withSession, { state: 'xyz' });

      expect(result.type).to.equal('error');
      expect(result.err).to.be.an.instanceof(TypeError);
      expect(result.err.message).to.include('pass application state as an object');
    });
  });

  describe('without session support', function() {
    var strategy = new Strategy({
      clientID: 'ABC123',
      callbackURL: CALLBACK_URL
    }, function() {});

    it('should error', async function() {
      var result = await run(strategy);

      expect(result.type).to.equal('error');
      expect(result.err.message).to.include('requires session support');
    });
  });

});

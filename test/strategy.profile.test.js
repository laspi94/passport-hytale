var Strategy = require('../lib/strategy')
  , OAuth2Strategy = require('passport-oauth2')
  , support = require('./support/provider');


describe('Strategy#userProfile', function() {

  var provider = new support.Provider();
  var strategy;

  before(function(done) {
    provider.start(function() {
      strategy = new Strategy({
        issuer: provider.issuer,
        clientID: support.CLIENT_ID,
        clientSecret: support.CLIENT_SECRET
      }, function() {});
      done();
    });
  });
  after(function(done) { provider.stop(done); });
  beforeEach(function() { provider.reset(); });

  function userProfile(accessToken) {
    return new Promise(function(resolve) {
      strategy.userProfile(accessToken, function(err, profile) {
        resolve({ err: err, profile: profile });
      });
    });
  }

  describe('fetching the profile', function() {
    var result, request;

    before(async function() {
      provider.reset();
      result = await userProfile('at-1');
      request = provider.received('/userinfo')[0];
    });

    it('should send the access token as a Bearer token', function() {
      expect(request.method).to.equal('GET');
      expect(request.headers['authorization']).to.equal('Bearer at-1');
      expect(request.url).to.equal('/userinfo');
    });

    it('should parse the profile', function() {
      var profile = result.profile;

      expect(result.err).to.equal(null);
      expect(profile.provider).to.equal('hytale');
      expect(profile.id).to.equal(support.SUBJECT);
      expect(profile.username).to.equal('Kweebec');
      expect(profile.gameProfile).to.deep.equal(support.GAME_PROFILE);
      expect(profile.sharedSource).to.equal(true);
      expect(profile).to.not.have.property('gameOwnership');
    });

    it('should set raw and json properties', function() {
      expect(result.profile._raw).to.be.a('string');
      expect(result.profile._json).to.deep.equal(JSON.parse(result.profile._raw));
    });
  });

  describe('when the access token is rejected', function() {
    it('should error with an InternalOAuthError', async function() {
      var result = await userProfile('expired');

      expect(result.err).to.be.an.instanceof(OAuth2Strategy.InternalOAuthError);
      expect(result.err.message).to.equal('Failed to fetch user profile');
      expect(result.err.oauthError.statusCode).to.equal(401);
    });
  });

  describe('when the response is not JSON', function() {
    it('should error', async function() {
      provider.handlers['/userinfo'] = function() {
        return { body: 'Hello, world.' };
      };

      var result = await userProfile('at-1');

      expect(result.err).to.be.an.instanceof(Error);
      expect(result.err.message).to.equal('Failed to parse user profile');
    });
  });

});

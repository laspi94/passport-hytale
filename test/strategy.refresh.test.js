var AuthTokenRefresh = require('passport-oauth2-refresh').AuthTokenRefresh
  , Strategy = require('../lib/strategy')
  , support = require('./support/provider');


describe('Strategy with passport-oauth2-refresh', function() {

  var provider = new support.Provider();

  before(function(done) { provider.start(done); });
  after(function(done) { provider.stop(done); });
  beforeEach(function() { provider.reset(); });

  function requestNewAccessToken(options) {
    var refresh = new AuthTokenRefresh();
    refresh.use(new Strategy(Object.assign({
      issuer: provider.issuer,
      clientID: support.CLIENT_ID
    }, options), function() {}));

    return new Promise(function(resolve) {
      refresh.requestNewAccessToken('hytale', 'rt-1', function(err, accessToken, refreshToken, params) {
        resolve({ err: err, accessToken: accessToken, refreshToken: refreshToken, params: params });
      });
    });
  }

  describe('for a confidential client', function() {
    var result, request;

    before(async function() {
      provider.reset();
      provider.handlers['/oauth2/token'] = function() {
        return { body: provider.tokenResponse({ access_token: 'at-2', refresh_token: 'rt-2' }) };
      };
      result = await requestNewAccessToken({ clientSecret: support.CLIENT_SECRET });
      request = provider.received('/oauth2/token')[0];
    });

    it('should authenticate with HTTP Basic', function() {
      var credentials = Buffer.from(support.CLIENT_ID + ':' + support.CLIENT_SECRET).toString('base64');
      expect(request.headers['authorization']).to.equal('Basic ' + credentials);
    });

    it('should send the refresh token without client_id or client_secret', function() {
      expect(request.form).to.deep.equal({
        grant_type: 'refresh_token',
        refresh_token: 'rt-1'
      });
    });

    it('should return the rotated tokens', function() {
      expect(result.err).to.equal(null);
      expect(result.accessToken).to.equal('at-2');
      expect(result.refreshToken).to.equal('rt-2');
      expect(result.params.id_token).to.be.a('string');
    });
  });

  describe('for a public client', function() {
    it('should send client_id without HTTP Basic', async function() {
      var result = await requestNewAccessToken({});
      var request = provider.received('/oauth2/token')[0];

      expect(result.err).to.equal(null);
      expect(request.headers['authorization']).to.equal(undefined);
      expect(request.form).to.deep.equal({
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
        client_id: support.CLIENT_ID
      });
    });
  });

  describe('when the refresh token was revoked', function() {
    it('should return the error from the token endpoint', async function() {
      provider.handlers['/oauth2/token'] = function() {
        return { status: 400, body: { error: 'invalid_grant', error_description: 'The refresh token has been revoked.' } };
      };

      var result = await requestNewAccessToken({ clientSecret: support.CLIENT_SECRET });

      expect(result.err.statusCode).to.equal(400);
      expect(JSON.parse(result.err.data).error).to.equal('invalid_grant');
    });
  });

});

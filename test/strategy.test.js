var Strategy = require('../lib/strategy')
  , OAuth2Strategy = require('passport-oauth2');


describe('Strategy', function() {

  var strategy = new Strategy({
    clientID: 'ABC123',
    clientSecret: 'secret'
  }, function() {});

  it('should be named hytale', function() {
    expect(strategy.name).to.equal('hytale');
  });

  it('should inherit from OAuth2Strategy', function() {
    expect(strategy).to.be.an.instanceof(OAuth2Strategy);
  });

  it('should use Hytale endpoints', function() {
    expect(strategy._oauth2._authorizeUrl).to.equal('https://connect.accounts.hytale.com/oauth2/auth');
    expect(strategy._oauth2._accessTokenUrl).to.equal('https://connect.accounts.hytale.com/oauth2/token');
    expect(strategy._userInfoURL).to.equal('https://connect.accounts.hytale.com/userinfo');
    expect(strategy._keys._url).to.equal('https://connect.accounts.hytale.com/.well-known/jwks.json');
    expect(strategy._issuer).to.equal('https://connect.accounts.hytale.com');
  });

  it('should always use PKCE with S256', function() {
    expect(strategy._pkceMethod).to.equal('S256');
  });

  it('should request the openid scope by default', function() {
    expect(strategy._scope).to.deep.equal([ 'openid' ]);
  });

  it('should keep state in the session under a key named after the issuer', function() {
    expect(strategy._key).to.equal('oauth2:connect.accounts.hytale.com');
  });

  it('should send the access token to the UserInfo endpoint as a Bearer token', function() {
    expect(strategy._oauth2._useAuthorizationHeaderForGET).to.equal(true);
  });

  describe('constructed with an issuer', function() {
    var strategy = new Strategy({
      clientID: 'ABC123',
      issuer: 'https://connect.example.test/'
    }, function() {});

    it('should derive endpoints from the issuer', function() {
      expect(strategy._issuer).to.equal('https://connect.example.test');
      expect(strategy._oauth2._authorizeUrl).to.equal('https://connect.example.test/oauth2/auth');
      expect(strategy._oauth2._accessTokenUrl).to.equal('https://connect.example.test/oauth2/token');
      expect(strategy._userInfoURL).to.equal('https://connect.example.test/userinfo');
      expect(strategy._keys._url).to.equal('https://connect.example.test/.well-known/jwks.json');
    });
  });

  describe('constructed with explicit endpoints', function() {
    var strategy = new Strategy({
      clientID: 'ABC123',
      authorizationURL: 'https://a.example.test/authorize',
      tokenURL: 'https://a.example.test/token',
      userInfoURL: 'https://a.example.test/me',
      jwksURL: 'https://a.example.test/keys'
    }, function() {});

    it('should use the given endpoints', function() {
      expect(strategy._oauth2._authorizeUrl).to.equal('https://a.example.test/authorize');
      expect(strategy._oauth2._accessTokenUrl).to.equal('https://a.example.test/token');
      expect(strategy._userInfoURL).to.equal('https://a.example.test/me');
      expect(strategy._keys._url).to.equal('https://a.example.test/keys');
    });
  });

  describe('constructed with a scope string', function() {
    var strategy = new Strategy({
      clientID: 'ABC123',
      scope: 'hytale:profile  account:shared_source'
    }, function() {});

    it('should add openid', function() {
      expect(strategy._scope).to.deep.equal([ 'openid', 'hytale:profile', 'account:shared_source' ]);
    });
  });

  describe('constructed with a scope array that includes openid', function() {
    var strategy = new Strategy({
      clientID: 'ABC123',
      scope: [ 'hytale:profile', 'openid', 'hytale:profile' ]
    }, function() {});

    it('should keep the order and drop duplicates', function() {
      expect(strategy._scope).to.deep.equal([ 'hytale:profile', 'openid' ]);
    });
  });

  describe('constructed with a state store that persists the code verifier', function() {
    var store = {
      store: function(req, verifier, state, meta, cb) {},
      verify: function(req, state, cb) {}
    };
    var strategy = new Strategy({ clientID: 'ABC123', store: store }, function() {});

    it('should use the store', function() {
      expect(strategy._stateStore).to.equal(store);
    });
  });

  describe('constructed without a verify callback', function() {
    it('should throw', function() {
      expect(function() {
        new Strategy({ clientID: 'ABC123' });
      }).to.throw(TypeError, 'HytaleStrategy requires a verify callback');
    });
  });

  describe('constructed without a clientID option', function() {
    it('should throw', function() {
      expect(function() {
        new Strategy({ clientSecret: 'secret' }, function() {});
      }).to.throw(TypeError, 'HytaleStrategy requires a clientID option');
    });
  });

  describe('constructed with only a verify callback', function() {
    it('should throw', function() {
      expect(function() {
        new Strategy(function() {});
      }).to.throw(TypeError, 'HytaleStrategy requires a clientID option');
    });
  });

  describe('constructed with a state store that cannot persist the code verifier', function() {
    it('should throw', function() {
      expect(function() {
        new Strategy({
          clientID: 'ABC123',
          store: {
            store: function(req, meta, cb) {},
            verify: function(req, state, cb) {}
          }
        }, function() {});
      }).to.throw(TypeError, 'HytaleStrategy requires a state store that persists the PKCE code verifier');
    });
  });

});

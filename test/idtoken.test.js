var crypto = require('crypto')
  , idToken = require('../lib/idtoken');


describe('idtoken.verify', function() {

  var pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  var ISSUER = 'https://connect.accounts.hytale.com';
  var CLIENT_ID = 'client-1';

  var keys = {
    get: function(kid, cb) {
      cb(null, kid === 'key-1' ? pair.publicKey : undefined);
    }
  };

  function b64(value) {
    return Buffer.from(typeof value == 'string' ? value : JSON.stringify(value)).toString('base64url');
  }

  function sign(claims, header) {
    var input = b64(Object.assign({ alg: 'RS256', kid: 'key-1' }, header)) + '.' + b64(claims);
    return input + '.' + crypto.sign('RSA-SHA256', Buffer.from(input), pair.privateKey).toString('base64url');
  }

  function claims(overrides) {
    var now = Math.floor(Date.now() / 1000);
    return Object.assign({ iss: ISSUER, sub: 'subject-1', aud: [ CLIENT_ID ], exp: now + 3600, iat: now }, overrides);
  }

  function verify(token, options) {
    return new Promise(function(resolve) {
      idToken.verify(token, Object.assign({ issuer: ISSUER, audience: CLIENT_ID, keys: keys }, options), function(err, claims, info) {
        resolve({ err: err, claims: claims, info: info });
      });
    });
  }

  it('should return the claims of a valid token', async function() {
    var result = await verify(sign(claims({ profile: { uuid: 'u', username: 'n' } })));

    expect(result.err).to.equal(null);
    expect(result.claims.sub).to.equal('subject-1');
    expect(result.claims.profile).to.deep.equal({ uuid: 'u', username: 'n' });
  });

  it('should accept an audience given as a string', async function() {
    var result = await verify(sign(claims({ aud: CLIENT_ID })));
    expect(result.claims.sub).to.equal('subject-1');
  });

  it('should accept an azp equal to the client ID', async function() {
    var result = await verify(sign(claims({ aud: [ CLIENT_ID, 'other' ], azp: CLIENT_ID })));
    expect(result.claims.sub).to.equal('subject-1');
  });

  it('should skip the at_hash check without an access token', async function() {
    var result = await verify(sign(claims({ at_hash: 'whatever' })));
    expect(result.claims.sub).to.equal('subject-1');
  });

  it('should accept a matching at_hash', async function() {
    var digest = crypto.createHash('sha256').update('access-token').digest();
    var result = await verify(sign(claims({ at_hash: digest.subarray(0, 16).toString('base64url') })), { accessToken: 'access-token' });
    expect(result.claims.sub).to.equal('subject-1');
  });

  it('should accept a token without at_hash', async function() {
    var result = await verify(sign(claims()), { accessToken: 'access-token' });
    expect(result.claims.sub).to.equal('subject-1');
  });

  it('should accept a token not yet valid within the clock tolerance', async function() {
    var result = await verify(sign(claims({ nbf: Math.floor(Date.now() / 1000) + 30 })), { clockTolerance: 60 });
    expect(result.claims.sub).to.equal('subject-1');
  });

  it('should reject a token without exp', async function() {
    var result = await verify(sign(claims({ exp: undefined })));
    expect(result.claims).to.equal(false);
    expect(result.info).to.deep.equal({ message: 'ID token is missing the exp claim' });
  });

  it('should reject a token that expires now', async function() {
    var result = await verify(sign(claims({ exp: Math.floor(Date.now() / 1000) })));
    expect(result.info).to.deep.equal({ message: 'ID token has expired' });
  });

  it('should reject a token without sub', async function() {
    var result = await verify(sign(claims({ sub: '' })));
    expect(result.info).to.deep.equal({ message: 'ID token is missing the sub claim' });
  });

  it('should reject a token without kid when no single key matches', async function() {
    var result = await verify(sign(claims(), { kid: undefined }));
    expect(result.info).to.deep.equal({ message: 'No signing key matches the ID token' });
  });

  it('should reject a token with a signature from another key', async function() {
    var other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    var input = b64({ alg: 'RS256', kid: 'key-1' }) + '.' + b64(claims());
    var token = input + '.' + crypto.sign('RSA-SHA256', Buffer.from(input), other.privateKey).toString('base64url');

    var result = await verify(token);
    expect(result.info).to.deep.equal({ message: 'Invalid ID token signature' });
  });

  it('should reject a token when the key cannot be used', async function() {
    var unusable = { get: function(kid, cb) { cb(null, 'not a key'); } };
    var result = await verify(sign(claims()), { keys: unusable });

    expect(result.info).to.deep.equal({ message: 'Invalid ID token signature' });
  });

  it('should reject an HS256 token', async function() {
    var input = b64({ alg: 'HS256', kid: 'key-1' }) + '.' + b64(claims());
    var token = input + '.' + crypto.createHmac('sha256', 'secret').update(input).digest('base64url');

    var result = await verify(token);
    expect(result.info).to.deep.equal({ message: 'Unexpected ID token signing algorithm: HS256' });
  });

  it('should reject a token whose payload is not an object', async function() {
    var result = await verify(b64({ alg: 'RS256' }) + '.' + b64('[1,2]') + '.sig');
    expect(result.info).to.deep.equal({ message: 'Malformed ID token' });
  });

  it('should reject a token whose header is not JSON', async function() {
    var result = await verify(b64('not json') + '.' + b64(claims()) + '.sig');
    expect(result.info).to.deep.equal({ message: 'Malformed ID token' });
  });

  it('should reject a value that is not a string', async function() {
    var result = await verify(undefined);
    expect(result.info).to.deep.equal({ message: 'Malformed ID token' });
  });

  it('should pass on errors from the key set', async function() {
    var failing = { get: function(kid, cb) { cb(new Error('network down')); } };
    var result = await verify(sign(claims()), { keys: failing });

    expect(result.err.message).to.equal('network down');
  });

});

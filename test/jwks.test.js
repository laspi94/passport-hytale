var crypto = require('crypto')
  , KeySet = require('../lib/jwks');


describe('KeySet', function() {

  function jwk(kid, extra) {
    var pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    return Object.assign(pair.publicKey.export({ format: 'jwk' }), { kid: kid, use: 'sig', alg: 'RS256' }, extra);
  }

  var KEY_1 = jwk('key-1');
  var KEY_2 = jwk('key-2');

  function source(keys) {
    var fetcher = function(url, cb) {
      fetcher.calls.push(url);
      setImmediate(function() {
        if (fetcher.error) { return cb(fetcher.error); }
        cb(null, typeof fetcher.body == 'string' ? fetcher.body : JSON.stringify(fetcher.body));
      });
    };
    fetcher.calls = [];
    fetcher.body = { keys: keys };
    return fetcher;
  }

  function get(set, kid) {
    return new Promise(function(resolve) {
      set.get(kid, function(err, key) { resolve({ err: err, key: key }); });
    });
  }

  it('should fetch the key set and return the key with the given ID', async function() {
    var fetch = source([ KEY_1, KEY_2 ]);
    var set = new KeySet({ url: 'https://issuer.test/jwks', fetch: fetch });

    var result = await get(set, 'key-2');

    expect(fetch.calls).to.deep.equal([ 'https://issuer.test/jwks' ]);
    expect(result.err).to.equal(null);
    expect(result.key.type).to.equal('public');
    expect(result.key.export({ format: 'jwk' }).n).to.equal(KEY_2.n);
  });

  it('should cache keys', async function() {
    var fetch = source([ KEY_1 ]);
    var set = new KeySet({ url: 'u', fetch: fetch });

    await get(set, 'key-1');
    var result = await get(set, 'key-1');

    expect(result.key).to.not.equal(undefined);
    expect(fetch.calls).to.have.length(1);
  });

  it('should not fetch again for an unknown key ID within the cooldown', async function() {
    var fetch = source([ KEY_1 ]);
    var set = new KeySet({ url: 'u', fetch: fetch });

    await get(set, 'key-1');
    var result = await get(set, 'key-2');

    expect(result.err).to.equal(null);
    expect(result.key).to.equal(undefined);
    expect(fetch.calls).to.have.length(1);
  });

  it('should fetch again for an unknown key ID after the cooldown', async function() {
    var fetch = source([ KEY_1 ]);
    var set = new KeySet({ url: 'u', fetch: fetch, cooldown: 0 });

    await get(set, 'key-1');
    fetch.body = { keys: [ KEY_1, KEY_2 ] };
    var result = await get(set, 'key-2');

    expect(result.key).to.not.equal(undefined);
    expect(fetch.calls).to.have.length(2);
  });

  it('should fetch again once the cache is stale', async function() {
    var fetch = source([ KEY_1 ]);
    var set = new KeySet({ url: 'u', fetch: fetch, maxAge: 0 });

    await get(set, 'key-1');
    await get(set, 'key-1');

    expect(fetch.calls).to.have.length(2);
  });

  it('should share one fetch between concurrent requests', async function() {
    var fetch = source([ KEY_1, KEY_2 ]);
    var set = new KeySet({ url: 'u', fetch: fetch });

    var results = await Promise.all([ get(set, 'key-1'), get(set, 'key-2'), get(set, 'key-1') ]);

    expect(fetch.calls).to.have.length(1);
    results.forEach(function(result) { expect(result.key).to.not.equal(undefined); });
  });

  it('should match a missing key ID only when there is a single key', async function() {
    var single = new KeySet({ url: 'u', fetch: source([ KEY_1 ]) });
    var multiple = new KeySet({ url: 'u', fetch: source([ KEY_1, KEY_2 ]) });

    expect((await get(single, undefined)).key).to.not.equal(undefined);
    expect((await get(multiple, undefined)).key).to.equal(undefined);
  });

  it('should ignore keys that cannot verify RS256 signatures', async function() {
    var ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    var weak = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ format: 'jwk' });
    var fetch = source([
      Object.assign(ec, { kid: 'ec' }),
      jwk('enc', { use: 'enc' }),
      jwk('ps256', { alg: 'PS256' }),
      Object.assign(weak, { kid: 'weak' }),
      { kty: 'RSA', kid: 'empty', n: '', e: '' },
      { kty: 'RSA', kid: 'invalid', n: 123, e: 'AQAB' },
      null,
      KEY_1
    ]);
    var set = new KeySet({ url: 'u', fetch: fetch });

    await get(set, 'key-1');

    expect(set._keys.map(function(k) { return k.kid; })).to.deep.equal([ 'key-1' ]);
  });

  it('should pass on fetch errors to every waiting request', async function() {
    var fetch = source([]);
    fetch.error = new Error('network down');
    var set = new KeySet({ url: 'u', fetch: fetch });

    var results = await Promise.all([ get(set, 'key-1'), get(set, 'key-1') ]);

    expect(fetch.calls).to.have.length(1);
    results.forEach(function(result) { expect(result.err.message).to.equal('network down'); });
  });

  it('should error when the key set is not JSON', async function() {
    var fetch = source([]);
    fetch.body = '<html>';
    var result = await get(new KeySet({ url: 'u', fetch: fetch }), 'key-1');

    expect(result.err.message).to.equal('Failed to parse JSON Web Key Set');
  });

  it('should error when the key set has no keys array', async function() {
    var fetch = source([]);
    fetch.body = { keys: {} };
    var result = await get(new KeySet({ url: 'u', fetch: fetch }), 'key-1');

    expect(result.err.message).to.equal('Invalid JSON Web Key Set');
  });

});

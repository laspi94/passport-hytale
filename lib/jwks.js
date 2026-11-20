// Load modules.
var crypto = require('crypto');


/**
 * Creates an instance of `KeySet`.
 *
 * Fetches and caches the RS256 signing keys published in the issuer's JSON
 * Web Key Set.  Keys are re-fetched once the cache is older than `maxAge`, and
 * also when a token names a key ID that is not cached (the issuer may have
 * rotated its keys), at most once per `cooldown`.  Concurrent fetches are
 * coalesced into a single request.
 *
 * @constructor
 * @param {object} options
 * @param {string} options.url - Location of the JSON Web Key Set.
 * @param {function} options.fetch - `fetch(url, cb)`, where `cb(err, body)`.
 * @param {number} [options.maxAge=600000] - Milliseconds.
 * @param {number} [options.cooldown=30000] - Milliseconds.
 * @access private
 */
function KeySet(options) {
  this._url = options.url;
  this._fetch = options.fetch;
  this._maxAge = options.maxAge !== undefined ? options.maxAge : 10 * 60 * 1000;
  this._cooldown = options.cooldown !== undefined ? options.cooldown : 30 * 1000;
  this._keys = null;
  this._fetchedAt = 0;
  this._pending = null;
}

/**
 * Get the public key with the given key ID.
 *
 * Calls back with `cb(null, undefined)` when no key matches.  A missing key ID
 * only matches when the key set holds exactly one key.
 *
 * @param {string} [kid]
 * @param {function} cb - `cb(err, key)`, where `key` is a `crypto.KeyObject`.
 */
KeySet.prototype.get = function(kid, cb) {
  var self = this;
  var age = Date.now() - this._fetchedAt;

  if (this._keys && age < this._maxAge) {
    var key = this._find(kid);
    if (key || age < this._cooldown) { return cb(null, key); }
  }

  this._refresh(function(err) {
    if (err) { return cb(err); }
    cb(null, self._find(kid));
  });
};

/**
 * @access private
 */
KeySet.prototype._find = function(kid) {
  var keys = this._keys;
  if (kid === undefined) { return keys.length === 1 ? keys[0].key : undefined; }
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].kid === kid) { return keys[i].key; }
  }
};

/**
 * @access private
 */
KeySet.prototype._refresh = function(cb) {
  var self = this;
  if (this._pending) { return this._pending.push(cb); }
  this._pending = [ cb ];

  this._fetch(this._url, function(err, body) {
    var keys;
    if (!err) {
      try {
        keys = parse(body);
      } catch (ex) {
        err = ex;
      }
    }
    if (!err) {
      self._keys = keys;
      self._fetchedAt = Date.now();
    }

    var callbacks = self._pending;
    self._pending = null;
    callbacks.forEach(function(callback) { callback(err); });
  });
};


/**
 * Parse a JSON Web Key Set, keeping the keys usable for RS256 signatures.
 *
 * @param {string} body
 * @returns {Array<{ kid: string, key: crypto.KeyObject }>}
 * @access private
 */
function parse(body) {
  var jwks;
  try {
    jwks = JSON.parse(body);
  } catch (ex) {
    throw new Error('Failed to parse JSON Web Key Set');
  }
  if (!jwks || !Array.isArray(jwks.keys)) { throw new Error('Invalid JSON Web Key Set'); }

  var keys = [];
  jwks.keys.forEach(function(jwk) {
    if (!jwk || jwk.kty !== 'RSA') { return; }
    if (jwk.use !== undefined && jwk.use !== 'sig') { return; }
    if (jwk.alg !== undefined && jwk.alg !== 'RS256') { return; }
    var key;
    try {
      key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    } catch (ex) {
      // Skip keys Node.js cannot import.
      return;
    }
    // RFC 7518, section 3.3: RS256 keys are 2048 bits or larger.
    if (key.asymmetricKeyDetails.modulusLength < 2048) { return; }
    keys.push({ kid: jwk.kid, key: key });
  });
  return keys;
}


// Expose constructor.
module.exports = KeySet;

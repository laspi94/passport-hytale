// Load modules.
var crypto = require('crypto');


/**
 * Verify an ID token issued by Hytale.
 *
 * Follows OpenID Connect Core 1.0, section 3.1.3.7, as it applies to Hytale:
 * the token must be signed with RS256 by a key in the issuer's JSON Web Key
 * Set, `iss` must equal the issuer, `aud` must contain the client ID, and the
 * token must not be expired.  When present, `azp` must equal the client ID,
 * `nbf` must not be in the future and `at_hash` must match the access token.
 *
 * The callback follows Passport's verify convention: `cb(err)` when the token
 * could not be checked (for example, the key set could not be fetched),
 * `cb(null, false, { message })` when the token is invalid, and
 * `cb(null, claims)` when it is valid.
 *
 * @param {string} token
 * @param {object} options
 * @param {string} options.issuer
 * @param {string} options.audience - Client ID.
 * @param {KeySet} options.keys
 * @param {number} [options.clockTolerance=0] - Seconds.
 * @param {string} [options.accessToken] - Checked against `at_hash`.
 * @param {function} cb
 * @access private
 */
exports.verify = function(token, options, cb) {
  var parts = typeof token == 'string' ? token.split('.') : [];
  if (parts.length !== 3) { return cb(null, false, { message: 'Malformed ID token' }); }

  var header, claims;
  try {
    header = decode(parts[0]);
    claims = decode(parts[1]);
  } catch (ex) {
    return cb(null, false, { message: 'Malformed ID token' });
  }
  if (!isObject(header) || !isObject(claims)) { return cb(null, false, { message: 'Malformed ID token' }); }
  if (header.alg !== 'RS256') {
    return cb(null, false, { message: 'Unexpected ID token signing algorithm: ' + header.alg });
  }

  options.keys.get(header.kid, function(err, key) {
    if (err) { return cb(err); }
    if (!key) { return cb(null, false, { message: 'No signing key matches the ID token' }); }

    var valid = false;
    try {
      valid = crypto.verify('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), key, Buffer.from(parts[2], 'base64url'));
    } catch (ex) {
      valid = false;
    }
    if (!valid) { return cb(null, false, { message: 'Invalid ID token signature' }); }

    var message = validateClaims(claims, options);
    if (message) { return cb(null, false, { message: message }); }

    cb(null, claims);
  });
};


/**
 * Check the claims of a signature-verified ID token.
 *
 * @returns {string|undefined} Failure message, if any.
 * @access private
 */
function validateClaims(claims, options) {
  if (claims.iss !== options.issuer) { return 'ID token not issued by expected OpenID provider'; }

  var aud = Array.isArray(claims.aud) ? claims.aud : [ claims.aud ];
  if (aud.indexOf(options.audience) === -1) { return 'ID token not intended for this client'; }
  if (claims.azp !== undefined && claims.azp !== options.audience) { return 'ID token not authorized for this client'; }

  var now = Math.floor(Date.now() / 1000);
  var tolerance = options.clockTolerance || 0;
  if (typeof claims.exp != 'number') { return 'ID token is missing the exp claim'; }
  if (now - tolerance >= claims.exp) { return 'ID token has expired'; }
  if (typeof claims.nbf == 'number' && now + tolerance < claims.nbf) { return 'ID token is not yet valid'; }

  if (typeof claims.sub != 'string' || !claims.sub) { return 'ID token is missing the sub claim'; }

  if (options.accessToken && claims.at_hash !== undefined) {
    var digest = crypto.createHash('sha256').update(options.accessToken, 'ascii').digest();
    if (claims.at_hash !== digest.subarray(0, digest.length / 2).toString('base64url')) {
      return 'Access token does not match the ID token';
    }
  }
}

function decode(segment) {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

function isObject(value) {
  return typeof value == 'object' && value !== null && !Array.isArray(value);
}

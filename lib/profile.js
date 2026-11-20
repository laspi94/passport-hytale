/**
 * Parse profile.
 *
 * Builds a normalized profile from Hytale claims, as found in the ID token or
 * returned by the UserInfo endpoint.  Claims that were not requested (and
 * granted) are left out.
 *
 * @param {object|string} json
 * @returns {object}
 * @access public
 */
exports.parse = function(json) {
  if ('string' == typeof json) {
    json = JSON.parse(json);
  }

  var profile = {};
  profile.id = json.sub;
  profile.displayName = '';

  // `hytale:profile` scope.
  var game = json.profile;
  if (game && typeof game == 'object') {
    profile.username = game.username;
    profile.displayName = game.username || '';
    profile.gameProfile = { uuid: game.uuid, username: game.username };
  }

  // `account:*` scopes.
  if (typeof json.shared_source == 'boolean') { profile.sharedSource = json.shared_source; }
  if (typeof json.game_ownership == 'boolean') { profile.gameOwnership = json.game_ownership; }
  if (typeof json.parental_managed == 'boolean') { profile.parentalManaged = json.parental_managed; }

  return profile;
};

var Profile = require('../lib/profile');


describe('Profile.parse', function() {

  describe('with every optional claim', function() {
    var profile = Profile.parse({
      sub: 'subject-1',
      profile: { uuid: 'b1c3e8a2-5d4f-4e6a-9b7c-2f1d0e9a8c76', username: 'Kweebec' },
      shared_source: false,
      game_ownership: true,
      parental_managed: true
    });

    it('should parse the profile', function() {
      expect(profile).to.deep.equal({
        id: 'subject-1',
        displayName: 'Kweebec',
        username: 'Kweebec',
        gameProfile: { uuid: 'b1c3e8a2-5d4f-4e6a-9b7c-2f1d0e9a8c76', username: 'Kweebec' },
        sharedSource: false,
        gameOwnership: true,
        parentalManaged: true
      });
    });
  });

  describe('with only the subject', function() {
    var profile = Profile.parse('{"sub":"subject-1"}');

    it('should parse the profile', function() {
      expect(profile).to.deep.equal({ id: 'subject-1', displayName: '' });
    });
  });

  describe('with a game profile without a username', function() {
    var profile = Profile.parse({ sub: 'subject-1', profile: { uuid: 'b1c3e8a2-5d4f-4e6a-9b7c-2f1d0e9a8c76' } });

    it('should use an empty display name', function() {
      expect(profile.displayName).to.equal('');
      expect(profile.gameProfile.uuid).to.equal('b1c3e8a2-5d4f-4e6a-9b7c-2f1d0e9a8c76');
    });
  });

  describe('with non-boolean account claims', function() {
    var profile = Profile.parse({ sub: 'subject-1', shared_source: 'true', game_ownership: null });

    it('should leave them out', function() {
      expect(profile).to.deep.equal({ id: 'subject-1', displayName: '' });
    });
  });

});

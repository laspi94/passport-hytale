var strategy = require('..');


describe('passport-hytale', function() {

  it('should export Strategy constructor as module', function() {
    expect(strategy).to.be.a('function');
    expect(strategy).to.equal(require('../lib/strategy'));
  });

  it('should export Strategy constructor', function() {
    expect(strategy.Strategy).to.be.a('function');
    expect(strategy.Strategy).to.equal(strategy);
  });

});

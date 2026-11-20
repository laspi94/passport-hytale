var chai = require('chai');


/**
 * Run `strategy.authenticate()` against a mock request and resolve with the
 * action the strategy took: `success`, `fail`, `error` or `redirect`.
 */
module.exports = function run(strategy, prepare, options) {
  return new Promise(function(resolve) {
    var request;
    chai.passport.use(strategy)
      .request(function(req) {
        request = req;
        if (prepare) { prepare(req); }
      })
      .success(function(user, info) { resolve({ type: 'success', user: user, info: info, req: request }); })
      .fail(function(challenge, status) { resolve({ type: 'fail', challenge: challenge, status: status, req: request }); })
      .error(function(err) { resolve({ type: 'error', err: err, req: request }); })
      .redirect(function(location) { resolve({ type: 'redirect', location: location, req: request }); })
      .authenticate(options);
  });
};

// Type tests for CommonJS consumers with `module: nodenext`.

import HytaleStrategy = require('passport-hytale');
import passport = require('passport');

passport.use(
    new HytaleStrategy.Strategy({ clientID: 'client-id' }, (accessToken, refreshToken, profile, done) => {
        done(null, { id: profile.id, sharedSource: profile.sharedSource });
    }),
);

const strategy: HytaleStrategy = new HytaleStrategy({ clientID: 'client-id' }, (a, r, p, done) => done(null, {}));

export = strategy;

// Type tests for ES module consumers.  The package resolves to itself through
// its `exports` field, as it would from an application's node_modules.

import HytaleStrategy, { Strategy, type Profile } from 'passport-hytale';
import passport from 'passport';

const strategy = new HytaleStrategy(
    { clientID: 'client-id', scope: ['hytale:profile'] },
    (accessToken, refreshToken, profile: Profile, done) => {
        done(null, { id: profile.id, username: profile.username });
    },
);

const same: typeof Strategy = HytaleStrategy;

passport.use(strategy);

export { same };

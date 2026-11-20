// Type tests for CommonJS consumers with `esModuleInterop`.

import HytaleStrategy from 'passport-hytale';
import passport from 'passport';

passport.use(
    new HytaleStrategy({ clientID: 'client-id' }, (accessToken, refreshToken, profile, done) => {
        done(null, { id: profile.id });
    }),
);

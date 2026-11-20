// Type tests for CommonJS consumers.  Checked with `npm run test:types`.

import HytaleStrategy = require('passport-hytale');
import {
    Strategy,
    Profile,
    StateStore,
    StateStoreVerifyCallback,
    TokenResponse,
    VerifyCallback,
} from 'passport-hytale';
import passport = require('passport');
import express = require('express');
import refresh = require('passport-oauth2-refresh');

// Verify callbacks are contextually typed without annotations.
const strategy = new HytaleStrategy(
    {
        clientID: 'client-id',
        clientSecret: 'client-secret',
        callbackURL: 'https://www.example.net/auth/hytale/callback',
        scope: ['hytale:profile', 'account:shared_source', 'offline'],
    },
    (accessToken, refreshToken, profile, done) => {
        const token: string = accessToken;
        const refresh: string | undefined = refreshToken;
        const id: string = profile.id;
        const provider: 'hytale' = profile.provider;
        const uuid: string | undefined = profile.gameProfile?.uuid;
        const username: string | undefined = profile.username;
        const sharedSource: boolean | undefined = profile.sharedSource;
        const sub: string = profile._json.sub;
        // @ts-expect-error profile is typed, not `any`.
        const notANumber: number = profile.id;
        // @ts-expect-error accessToken is typed, not `any`.
        const notABoolean: boolean = accessToken;
        // @ts-expect-error refreshToken may be undefined.
        const notOptional: string = refreshToken;
        done(null, { id, token, refresh, provider, uuid, username, sharedSource, sub, notANumber, notABoolean, notOptional });
    },
);

new HytaleStrategy({ clientID: 'client-id', passReqToCallback: true }, (req, accessToken, refreshToken, profile, done) => {
    const request: express.Request = req;
    done(null, { id: profile.id, url: request.url });
});

// Forms that receive the token response take annotated parameters.
new HytaleStrategy(
    { clientID: 'client-id' },
    (
        accessToken: string,
        refreshToken: string | undefined,
        params: TokenResponse,
        profile: Profile,
        done: VerifyCallback,
    ) => {
        const idToken: string = params.id_token;
        const expiresIn: number | undefined = params.expires_in;
        done(null, false, { message: `${idToken} ${expiresIn} ${profile.id}` });
    },
);

new HytaleStrategy(
    { clientID: 'client-id', passReqToCallback: true },
    (
        req: express.Request,
        accessToken: string,
        refreshToken: string | undefined,
        params: TokenResponse,
        profile: Profile,
        done: VerifyCallback,
    ) => {
        done(null, { id: profile.id, url: req.url, idToken: params.id_token });
    },
);

// Named export, scope string, other options.
const named = new Strategy(
    {
        clientID: 'client-id',
        scope: 'openid hytale:profile',
        clockTolerance: 30,
        issuer: 'https://connect.accounts.hytale.com',
        store: true,
        proxy: true,
    },
    (accessToken, refreshToken, profile, done: VerifyCallback) => done(null, profile),
);

// Custom state store.
const store: StateStore = {
    store(req, verifier, state, meta, callback) {
        callback(null, `${verifier}:${meta.clientID}`);
    },
    verify(req: express.Request, providedState: string, callback: StateStoreVerifyCallback) {
        callback(null, providedState);
    },
};
new HytaleStrategy({ clientID: 'client-id', store }, (a, r, p, done) => done(null, {}));

// Works with Passport and passport-oauth2-refresh.
passport.use(strategy);
passport.use('hytale-named', named);
refresh.use(strategy);
passport.authenticate('hytale', { scope: ['hytale:profile'], failureRedirect: '/login' });

const name: 'hytale' = strategy.name;
strategy.userProfile('access-token', (err, profile) => {
    if (err) {
        const message: string = err.message;
        return message;
    }
    const sharedSource: boolean | undefined = profile?.sharedSource;
    return sharedSource;
});

// The profile is a Passport profile.
declare const hytaleProfile: Profile;
const passportProfile: passport.Profile = hytaleProfile;

// @ts-expect-error clientID is required.
new HytaleStrategy({}, (a, r, p, done) => done(null, {}));

// @ts-expect-error passReqToCallback must be true to receive the request.
new HytaleStrategy({ clientID: 'client-id' }, (req: express.Request, a: string, r: string | undefined, p: Profile, done: VerifyCallback) => done(null, {}));

// @ts-expect-error clientSecret must be a string.
new HytaleStrategy({ clientID: 'client-id', clientSecret: 42 }, (a, r, p, done) => done(null, {}));

export { name, passportProfile };

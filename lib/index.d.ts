import { Request } from 'express';
import { OutgoingHttpHeaders } from 'http';
import passport = require('passport');
import OAuth2Strategy = require('passport-oauth2');

/**
 * `OAuth2Strategy` without its static members, so that `HytaleStrategy` can
 * expose its own `Strategy` while its instances remain `OAuth2Strategy`
 * instances (as required by `passport-oauth2-refresh`, for example).
 */
declare const OAuth2StrategyBase: new (...args: any[]) => OAuth2Strategy;

/**
 * Passport strategy for "Sign in with Hytale" (OpenID Connect).
 *
 * PKCE (`S256`) and `state` are always used.  The profile passed to the verify
 * callback is built from the validated ID token.
 */
declare class HytaleStrategy extends OAuth2StrategyBase {
    /**
     * Parameter types are inferred for this form.  To also receive the token
     * response, annotate the parameters (see `VerifyFunctionWithParams`).
     */
    constructor(options: HytaleStrategy.StrategyOptions, verify: HytaleStrategy.VerifyFunction);
    constructor(options: HytaleStrategy.StrategyOptions, verify: HytaleStrategy.VerifyFunctionWithParams);
    constructor(options: HytaleStrategy.StrategyOptionsWithRequest, verify: HytaleStrategy.VerifyFunctionWithRequest);
    constructor(
        options: HytaleStrategy.StrategyOptionsWithRequest,
        verify: HytaleStrategy.VerifyFunctionWithRequestAndParams,
    );

    name: 'hytale';

    /**
     * Fetch the account's current claims from the UserInfo endpoint.
     *
     * Not called during sign-in; useful after refreshing tokens.
     */
    userProfile(accessToken: string, done: (err: Error | null, profile?: HytaleStrategy.Profile) => void): void;
}

declare namespace HytaleStrategy {
    type Strategy = HytaleStrategy;
    const Strategy: typeof HytaleStrategy;

    /** Scopes documented by Hytale. */
    type KnownScope =
        | 'openid'
        | 'hytale:profile'
        | 'account:shared_source'
        | 'account:game_ownership'
        | 'account:parental_managed'
        | 'offline';

    /** A scope.  `openid` is always added by the strategy. */
    type Scope = KnownScope | (string & {});

    /** Game profile the user picked at sign-in (`hytale:profile` scope). */
    interface GameProfile {
        uuid: string;
        username: string;
    }

    /**
     * Claims from the ID token, or from the UserInfo endpoint (which omits the
     * JWT-specific ones).
     */
    interface Claims {
        /** Stable, per-application anonymous identifier (43-character base64url). */
        sub: string;
        iss?: string;
        aud?: string | string[];
        exp?: number;
        iat?: number;
        auth_time?: number;
        azp?: string;
        sid?: string;
        jti?: string;
        at_hash?: string;
        /** `hytale:profile` scope. */
        profile?: GameProfile;
        /** `account:shared_source` scope. */
        shared_source?: boolean;
        /** `account:game_ownership` scope. */
        game_ownership?: boolean;
        /** `account:parental_managed` scope. */
        parental_managed?: boolean;
        [claim: string]: unknown;
    }

    interface Profile extends passport.Profile {
        provider: 'hytale';
        /** The `sub` claim. */
        id: string;
        /** Game profile username, or an empty string without the `hytale:profile` scope. */
        displayName: string;
        /** Game profile username (`hytale:profile` scope). */
        username?: string;
        /** `hytale:profile` scope. */
        gameProfile?: GameProfile;
        /** `account:shared_source` scope. */
        sharedSource?: boolean;
        /** `account:game_ownership` scope. */
        gameOwnership?: boolean;
        /** `account:parental_managed` scope. */
        parentalManaged?: boolean;
        /** JSON text of the claims. */
        _raw: string;
        _json: Claims;
    }

    /** Token endpoint response, without `refresh_token` (passed separately). */
    interface TokenResponse {
        access_token: string;
        token_type: string;
        expires_in?: number;
        scope?: string;
        id_token: string;
        [key: string]: unknown;
    }

    interface Metadata {
        authorizationURL: string;
        tokenURL: string;
        clientID: string;
        callbackURL?: string;
    }

    type StateStoreVerifyCallback = (err: Error | null, ok?: string | false, stateOrInfo?: unknown) => void;

    /**
     * State store that also persists the PKCE code verifier.
     *
     * `verify` calls back with the stored code verifier as `ok`.
     */
    interface StateStore {
        store(
            req: Request,
            verifier: string,
            state: unknown,
            meta: Metadata,
            callback: (err: Error | null, handle?: string) => void,
        ): void;
        verify:
            | ((req: Request, providedState: string, callback: StateStoreVerifyCallback) => void)
            | ((req: Request, providedState: string, meta: Metadata, callback: StateStoreVerifyCallback) => void);
    }

    type VerifyCallback = (err?: Error | null | unknown, user?: Express.User | false, info?: object) => void;

    /** `refreshToken` is `undefined` unless the `offline` scope was granted. */
    type VerifyFunction = (
        accessToken: string,
        refreshToken: string | undefined,
        profile: Profile,
        done: VerifyCallback,
    ) => void;

    type VerifyFunctionWithParams = (
        accessToken: string,
        refreshToken: string | undefined,
        params: TokenResponse,
        profile: Profile,
        done: VerifyCallback,
    ) => void;

    type VerifyFunctionWithRequest = (
        req: Request,
        accessToken: string,
        refreshToken: string | undefined,
        profile: Profile,
        done: VerifyCallback,
    ) => void;

    type VerifyFunctionWithRequestAndParams = (
        req: Request,
        accessToken: string,
        refreshToken: string | undefined,
        params: TokenResponse,
        profile: Profile,
        done: VerifyCallback,
    ) => void;

    interface StrategyOptionsBase {
        /** Client ID issued by Hytale. */
        clientID: string;
        /** Client secret, for confidential clients.  Omit it for public clients. */
        clientSecret?: string | undefined;
        /** Redirect URI registered for the client. */
        callbackURL?: string | undefined;
        /** Scopes to request.  Request only scopes granted to the client. */
        scope?: Scope | Scope[] | undefined;
        /** Seconds of clock skew allowed when checking `exp`.  Defaults to `0`. */
        clockTolerance?: number | undefined;
        /** Defaults to `https://connect.accounts.hytale.com`. */
        issuer?: string | undefined;
        authorizationURL?: string | undefined;
        tokenURL?: string | undefined;
        userInfoURL?: string | undefined;
        jwksURL?: string | undefined;
        /** Custom state store, or `true` to store application state in the session. */
        store?: StateStore | true | undefined;
        /** Session key for the state.  Defaults to `oauth2:connect.accounts.hytale.com`. */
        sessionKey?: string | undefined;
        /** Trust proxy headers when resolving a relative `callbackURL`. */
        proxy?: boolean | undefined;
        customHeaders?: OutgoingHttpHeaders | undefined;
    }

    interface StrategyOptions extends StrategyOptionsBase {
        passReqToCallback?: false | undefined;
    }

    interface StrategyOptionsWithRequest extends StrategyOptionsBase {
        passReqToCallback: true;
    }
}

export = HytaleStrategy;

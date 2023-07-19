import { SessionStrategy } from './index.js';
import type { SessionStorage } from '@remix-run/server-runtime';
import type { Camelize } from 'camelize-ts';
import type { JsonObject, JsonValue, SetOptional } from 'type-fest';

export type TokenError = Error & { code: string; };

export interface Auth0UserProfile extends JsonObject {
  sub: string;
  name: string;
  picture: string;
  nickname: string;
  updatedAt: string;
}

export interface Auth0Credentials extends JsonObject {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

export interface UserCredentials {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  expiresAt: number;
  lastRefreshed: number;
}

export type Auth0CredentialsCallback = (tokens: UserCredentials) => void;

/**
 * @see https://auth0.com/docs/api/authentication#user-profile
 * @see https://auth0.com/docs/manage-users/user-accounts/user-profiles/normalized-user-profile-schema
 */
export interface UserProfile {
  sub: string;
  name: string;
  picture: string;
  nickname: string;
  givenName?: string;
  familyName?: string;
  middleName?: string;
  preferredUsername?: string;
  profile?: string;
  website?: string;
  email?: string;
  emailVerified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phoneNumber?: string;
  phoneNumberVerified?: boolean;
  address?: {
    country: string;
  };
  updatedAt: string;
  [key: Camelize<string>]: Camelize<JsonValue>;
}

export interface ClientCredentials {
  clientID: string;
  clientSecret: string;
  audience: string;
  organization?: string | undefined;
  usePost?: boolean | undefined;
}

export interface SessionStore {
  key: string;
  store: SessionStorage;
  strategy?: SessionStrategy;
}

export type CacheGetFunction = (accessToken: string) => Promise<UserProfile>;
export type CacheSetFunction = (accessToken: string, profile: UserProfile, expiresAt: number) => Promise<void>;

export interface Auth0RemixOptions {
  callbackURL: string;
  failedLoginRedirect: string;
  refreshTokenRotationEnabled?: boolean;
  clientDetails: SetOptional<ClientCredentials, 'audience'> & { domain: string };
  session: SetOptional<SessionStore, 'key'>;
  credentialsCallback?: Auth0CredentialsCallback;
  profileCacheGet?: CacheGetFunction;
  profileCacheSet?: CacheSetFunction;
}

interface BaseAuthorizeOptions {
  callbackParams?: Record<string, string>;
  forceSignup?: boolean;
  connection?: string;
}

// Make the `silentAuth` and `forceLogin` options mutually exclusive
export type AuthorizeOptions =
  BaseAuthorizeOptions & { silentAuth?: boolean; forceLogin?: never; }
  | BaseAuthorizeOptions & { forceLogin?: boolean; silentAuth?: never; }

export interface HandleCallbackOptions {
  onSuccessRedirect?: string;
  onFailureRedirect?: string;
}

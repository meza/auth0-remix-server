import type { Session, SessionStorage } from '@remix-run/node';
import type { Camelize } from 'camelize-ts';
import type { errors as JoseErrors } from 'jose';
import type { JsonObject, JsonValue, SetOptional } from 'type-fest';

export type TokenError = JoseErrors.JOSEError;

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

export interface UserCredentials extends JsonObject {
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
}

export interface CsrfSessionStorage extends SessionStorage {
  verifyToken?<T extends Session>(tokenToCheck: string, session: T): boolean;
  getToken?<T extends Session>(session: T): string | undefined;
}

export interface SessionStore {
  key: string;
  store: SessionStorage | CsrfSessionStorage;
}

interface BaseAuth0RemixOptions {
  callbackURL: string;
  failedLoginRedirect: string;
  refreshTokenRotationEnabled?: boolean;
  clientDetails: SetOptional<ClientCredentials, 'audience'> & { domain: string };
  session: SetOptional<SessionStore, 'key'>;
  credentialsCallback?: Auth0CredentialsCallback;
}

export type Auth0RemixOptions =
  | BaseAuth0RemixOptions & { csrfTokenSecret: string }
  | BaseAuth0RemixOptions & { csrfSession: SessionStore };

export interface AuthorizeOptions {
  forceLogin?: boolean;
  forceSignup?: boolean;
}

export interface HandleCallbackOptions {
  onSuccessRedirect?: string | [string, HeadersInit | (() => HeadersInit) | (() => Promise<HeadersInit>)];
}

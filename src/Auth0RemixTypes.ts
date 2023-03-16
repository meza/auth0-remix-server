import type { SessionStorage } from '@remix-run/node';
// import type { JOSEError } from 'jose/dist/types/util/errors';

export type TokenError = Error & { code: string; };

export interface Auth0UserProfile {
  [key: string]: string | boolean | number | object;
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
  },
  updatedAt: string;
  [key: string]: string | boolean | number | object | undefined
}

export interface ClientCredentials {
  clientID: string;
  clientSecret: string;
  audience: string;
  organization?: string | undefined;
}

export interface SessionStore {
  key: string;
  store: SessionStorage;
}

export interface Auth0RemixOptions {
  callbackURL: string;
  failedLoginRedirect: string;
  refreshTokenRotationEnabled?: boolean;
  clientDetails: Omit<ClientCredentials, 'audience'> & { audience?: string; domain: string; };
  session: Omit<SessionStore, 'key'> & { key?: string; };
  credentialsCallback?: Auth0CredentialsCallback;
}

export interface AuthorizeOptions {
  forceLogin?: boolean;
  forceSignup?: boolean;
}

export interface HandleCallbackOptions {
  onSuccessRedirect?: string;
}

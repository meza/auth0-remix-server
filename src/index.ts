import { redirect } from '@remix-run/node';
import * as jose from 'jose';
import { generateCsrfCookie, getCsrfCookieStorage, getCsrfToken, verifyCsrfToken } from './lib/csrfToken.js';
import { ensureDomain } from './lib/ensureDomainFormat.js';
import { mergeHeaders } from './lib/mergeHeaders.js';
import { getCredentials, saveUserToSession } from './lib/session.js';
import { transformUserData } from './lib/transformUserData.js';
import type {
  Auth0Credentials,
  Auth0CredentialsCallback,
  Auth0RemixOptions,
  Auth0UserProfile,
  ClientCredentials,
  HandleCallbackOptions,
  SessionStore,
  UserCredentials,
  UserProfile,
  TokenError,
  AuthorizeOptions
} from './Auth0RemixTypes.js';
import type { AppLoadContext } from '@remix-run/node';

export enum Token {
  ID = 'id',
  ACCESS = 'access'
}

interface Auth0Urls {
  authorizationURL: string;
  openIDConfigurationURL: string;
  jwksURL: string;
  userProfileUrl: string;
  tokenURL: string;
}

const noop = () => { /* empty */ };

export class Auth0RemixServer {
  private readonly domain: string;
  private readonly refreshTokenRotationEnabled: boolean;
  private readonly callbackURL: string;
  private readonly failedLoginRedirect: string;
  private readonly jwks: ReturnType<typeof jose.createRemoteJWKSet>;
  private readonly clientCredentials: ClientCredentials;
  private readonly session: SessionStore;
  private readonly tokenSession: SessionStore;
  private readonly auth0Urls: Auth0Urls;
  private readonly credentialsCallback: Auth0CredentialsCallback;
  private readonly shouldHandleCookie: boolean = false;

  constructor(auth0RemixOptions: Auth0RemixOptions) {
    this.domain = ensureDomain(auth0RemixOptions.clientDetails.domain);

    /**
     * Refresh token rotation allows us to store the refresh tokens in the user's session.
     * It is off by default because it requires an explicit setup in Auth0.
     *
     * @see https://auth0.com/docs/tokens/refresh-tokens/refresh-token-rotation
     * @see https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/#Refresh-Token-Rotation
     */
    this.refreshTokenRotationEnabled = auth0RemixOptions.refreshTokenRotationEnabled || false;

    this.failedLoginRedirect = auth0RemixOptions.failedLoginRedirect;
    this.callbackURL = auth0RemixOptions.callbackURL;

    this.clientCredentials = {
      clientID: auth0RemixOptions.clientDetails.clientID,
      clientSecret: auth0RemixOptions.clientDetails.clientSecret,
      audience: auth0RemixOptions.clientDetails.audience || `${this.domain}/api/v2/`,
      organization: auth0RemixOptions.clientDetails.organization
    };
    this.session = {
      store: auth0RemixOptions.session.store,
      key: auth0RemixOptions.session.key || 'user'
    };

    if ('csrfTokenSecret' in auth0RemixOptions) {
      this.tokenSession = {
        store: getCsrfCookieStorage(auth0RemixOptions.csrfTokenSecret),
        key: 'csrfToken'
      };
      this.shouldHandleCookie = true;
    } else {
      this.tokenSession = auth0RemixOptions.csrfSession;
    }

    this.auth0Urls = {
      tokenURL: `${this.domain}/oauth/token`,
      userProfileUrl: `${this.domain}/userinfo`,
      authorizationURL: `${this.domain}/authorize`,
      jwksURL: `${this.domain}/.well-known/jwks.json`,
      openIDConfigurationURL: `${this.domain}/.well-known/openid-configuration`
    };

    this.credentialsCallback = auth0RemixOptions.credentialsCallback || noop;

    this.jwks = jose.createRemoteJWKSet(new URL(this.auth0Urls.jwksURL));
  }

  public async decodeToken(token: string, type: Token) {
    const { payload } = await jose.jwtVerify(token, this.jwks, {
      issuer: this.domain + '/',
      audience: type === Token.ACCESS ? this.clientCredentials.audience : this.clientCredentials.clientID
    });
    return payload;
  }

  public async verifyToken(token: string, type: Token) {
    await this.decodeToken(token, type);
  }

  public async isValid(token: string, type: Token) {
    try {
      await this.verifyToken(token, type);
      return true;
    } catch (_) {
      return false;
    }
  }

  public async authorize(request: Request, opts: AuthorizeOptions = {}) {
    console.log('[Auth0-Server] authorize');

    const scope = [
      'offline_access', // required for refresh token
      'openid', // required for id_token and the /userinfo api endpoint
      'profile',
      'email'
    ];
    const authorizationURL = new URL(this.auth0Urls.authorizationURL);
    authorizationURL.searchParams.set('response_type', 'code');
    authorizationURL.searchParams.set('response_mode', 'form_post');
    authorizationURL.searchParams.set('client_id', this.clientCredentials.clientID);
    authorizationURL.searchParams.set('redirect_uri', this.callbackURL);
    authorizationURL.searchParams.set('scope', scope.join(' '));
    authorizationURL.searchParams.set('audience', this.clientCredentials.audience);

    if (this.clientCredentials.organization) {
      authorizationURL.searchParams.set('organization', this.clientCredentials.organization);
    }
    if (opts.forceLogin) {
      authorizationURL.searchParams.set('prompt', 'login');
    }
    if (opts.forceSignup) {
      authorizationURL.searchParams.set('screen_hint', 'signup');
    }

    if (!this.shouldHandleCookie) {
      console.log('** not handling cookie');
      const token = await getCsrfToken(request, this.tokenSession);
      if (!token) {
        console.error('Missing token');
        throw redirect(this.failedLoginRedirect);
      }
      authorizationURL.searchParams.set('state', token);
      throw redirect(authorizationURL.toString());
    }

    const { cookie, token } = await generateCsrfCookie(request, this.tokenSession);
    authorizationURL.searchParams.set('state', token);
    console.log({ cookie: cookie, token: token });
    throw redirect(authorizationURL.toString(), {
      headers: { 'set-cookie': cookie }
    });
  }

  public async handleCallback(request: Request, options?: HandleCallbackOptions): Promise<UserCredentials> {
    console.log('[Auth0-Server] handleCallback');
    const formData = await request.formData();
    const code = formData.get('code');
    const state = formData.get('state');

    if (!code) {
      console.error('No code found in callback');
      throw redirect(this.failedLoginRedirect);
    }

    if (!state) {
      console.error('No state found in callback');
      throw redirect(this.failedLoginRedirect);
    }

    if (!await verifyCsrfToken(request, this.tokenSession, state.toString())) {
      console.error('Invalid CSRF token');
      throw redirect(this.failedLoginRedirect);
    }

    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('client_id', this.clientCredentials.clientID);
    body.set('client_secret', this.clientCredentials.clientSecret);
    body.set('code', code.toString());
    body.set('redirect_uri', this.callbackURL);

    console.log('** fetching');
    const response = await fetch(this.auth0Urls.tokenURL, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      body: body.toString()
    });

    if (!response.ok) {
      console.error('Failed to get token from Auth0');
      throw redirect(this.failedLoginRedirect);
    }

    const data = (await response.json()) as Auth0Credentials;
    const userData: UserCredentials = {
      accessToken: data.access_token,
      expiresIn: data.expires_in,
      lastRefreshed: Date.now(),
      expiresAt: Date.now() + data.expires_in * 1000
    };

    if (this.refreshTokenRotationEnabled) {
      userData.refreshToken = data.refresh_token;
    }

    this.credentialsCallback({ ...userData, refreshToken: data.refresh_token });

    if (options?.onSuccessRedirect) {
      const authHeaders = await saveUserToSession(request, userData, this.session);
      throw await this.getSuccessRedirect(authHeaders, options.onSuccessRedirect);
    }

    return userData;
  }

  public logout(redirectTo: string, headers?: HeadersInit) {
    const logoutURL = new URL(`${this.domain}/v2/logout`);
    logoutURL.searchParams.set('client_id', this.clientCredentials.clientID);
    logoutURL.searchParams.set('returnTo', redirectTo);
    throw redirect(logoutURL.toString(), {
      headers: headers || {}
    });
  }

  public async getUser(request: Request, context: AppLoadContext): Promise<UserProfile> {
    let credentials: UserCredentials;

    try {
      credentials = await getCredentials(request, this.session);
    } catch (err) {
      console.error('No credentials found');
      throw redirect(this.failedLoginRedirect);
    }

    try {
      await this.decodeToken(credentials.accessToken, Token.ACCESS);
      return await this.getUserProfile(credentials);
    } catch (error) {
      if ((error as TokenError).code === 'ERR_JWT_EXPIRED') {
        if (!context.refresh) {
          context.refresh = this.refreshCredentials(credentials);
          const result = (await context.refresh) as UserCredentials;
          const headers = await saveUserToSession(request, result, this.session);
          throw redirect(request.url, {
            headers: headers
          });
        }

        await context.refresh;
        return await this.getUser(request, context);
      }

      console.error('Failed to verify JWT', error);
      throw redirect(this.failedLoginRedirect);
    }
  }

  private async refreshCredentials(credentials: UserCredentials): Promise<UserCredentials> {
    if (!credentials.refreshToken) {
      console.error('No refresh token found within the credentials.');
      throw redirect(this.failedLoginRedirect);
    }

    const body = new URLSearchParams();
    body.set('grant_type', 'refresh_token');
    body.set('client_id', this.clientCredentials.clientID);
    body.set('client_secret', this.clientCredentials.clientSecret);
    body.set('refresh_token', credentials.refreshToken);

    const response = await fetch(this.auth0Urls.tokenURL, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      body: body.toString()
    });

    if (!response.ok) {
      console.error('Failed to refresh token from Auth0');
      throw redirect(this.failedLoginRedirect);
    }
    const data = (await response.json()) as Auth0Credentials;
    const userData: UserCredentials = {
      accessToken: data.access_token,
      expiresIn: data.expires_in,
      lastRefreshed: Date.now(),
      expiresAt: Date.now() + data.expires_in * 1000
    };

    if (this.refreshTokenRotationEnabled) {
      userData.refreshToken = data.refresh_token;
    }

    this.credentialsCallback({ ...userData, refreshToken: data.refresh_token });

    return userData;
  }

  private async getUserProfile(credentials: UserCredentials): Promise<UserProfile> {
    const response = await fetch(this.auth0Urls.userProfileUrl, {
      headers: {
        Authorization: `Bearer ${credentials.accessToken}`
      }
    });

    if (!response.ok) {
      console.error('Failed to get user profile from Auth0');
      throw redirect(this.failedLoginRedirect);
    }

    const data = (await response.json()) as Auth0UserProfile;
    return transformUserData(data);
  }

  private async getSuccessRedirect(authHeaders: HeadersInit, redirectOpts: NonNullable<HandleCallbackOptions['onSuccessRedirect']>) {
    let path: string, redirectHeaders: HeadersInit | undefined;

    if (typeof redirectOpts === 'string') {
      path = redirectOpts;
    } else if (typeof redirectOpts[1] === 'function') {
      path = redirectOpts[0];
      redirectHeaders = await redirectOpts[1]();
    } else {
      path = redirectOpts[0];
      redirectHeaders = redirectOpts[1];
    }

    return redirect(path, {
      headers: redirectHeaders ? mergeHeaders(redirectHeaders, authHeaders) : authHeaders
    });
  }

  // private async getFailureRedirect(request: Request, destroyCsrfTokenCookie = true) {
  //   let headers;
  //
  //   if (destroyCsrfTokenCookie) {
  //     const { store } = this.tokenSession;
  //     const session = await store.getSession(request.headers.get('cookie'));
  //     headers = { 'set-cookie': await store.destroySession(session) };
  //   }
  //
  //   return redirect(this.failedLoginRedirect, headers ? { headers: headers } : undefined);
  // }
}

export { generateCsrfToken } from './lib/csrfToken.js';
export * from './Auth0RemixTypes.js';

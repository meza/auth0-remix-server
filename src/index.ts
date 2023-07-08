import { redirect } from '@remix-run/server-runtime';
import * as jose from 'jose';
import { ensureDomain } from './lib/ensureDomainFormat.js';
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
import type { AppLoadContext } from '@remix-run/server-runtime';

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
  private readonly auth0Urls: Auth0Urls;
  private readonly credentialsCallback: Auth0CredentialsCallback;

  constructor(auth0RemixOptions: Auth0RemixOptions) {
    console.error('This is working ffs debug 0');
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
      organization: auth0RemixOptions.clientDetails.organization,
      usePost: auth0RemixOptions.clientDetails.usePost
    };
    this.session = {
      store: auth0RemixOptions.session.store,
      key: auth0RemixOptions.session.key || 'user'
    };
    this.auth0Urls = {
      tokenURL: `${this.domain}/oauth/token`,
      userProfileUrl: `${this.domain}/userinfo`,
      authorizationURL: `${this.domain}/authorize`,
      jwksURL: `${this.domain}/.well-known/jwks.json`,
      openIDConfigurationURL: `${this.domain}/.well-known/openid-configuration`
    };

    // eslint-disable-next-line @typescript-eslint/no-empty-function
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

  public authorize(opts: AuthorizeOptions = {}) {

    const cbUrl = new URL(this.callbackURL);
    if (opts.callbackParams) {
      Object.entries(opts.callbackParams).forEach(([key, value]) => {
        cbUrl.searchParams.set(key, value);
      });
    }

    const authorizationURL = new URL(this.auth0Urls.authorizationURL);
    authorizationURL.searchParams.set('redirect_uri', cbUrl.toString());

    this.setAuthorizationParameters(authorizationURL, opts);

    throw redirect(authorizationURL.toString());
  }

  private setAuthorizationParameters(authorizationURL: URL, opts: AuthorizeOptions = {}) {
    const scope = [
      'offline_access', // required for refresh token
      'openid', // required for id_token and the /userinfo api endpoint
      'profile',
      'email'
    ];

    authorizationURL.searchParams.set('response_type', 'code');

    if (this.clientCredentials.usePost !== false) {
      authorizationURL.searchParams.set('response_mode', 'form_post');
    }

    authorizationURL.searchParams.set('client_id', this.clientCredentials.clientID);
    authorizationURL.searchParams.set('scope', scope.join(' '));
    authorizationURL.searchParams.set('audience', this.clientCredentials.audience);
    if (this.clientCredentials.organization) {
      authorizationURL.searchParams.set('organization', this.clientCredentials.organization);
    }
    if (opts.forceLogin) {
      authorizationURL.searchParams.set('prompt', 'login');
    }
    if (opts.silentAuth) {
      authorizationURL.searchParams.set('prompt', 'none');
    }
    if (opts.forceSignup) {
      authorizationURL.searchParams.set('screen_hint', 'signup');
    }
    if (opts.connection) {
      authorizationURL.searchParams.set('connection', opts.connection);
    }

  }

  private async getCodeFromRequest(request: Request): Promise<string | null> {
    try {
      const formData = await request.formData();
      if (formData.has('code')) {
        return String(formData.get('code'));
      }
    } catch (e) {
      const url = new URL(request.url);
      if (url.searchParams.has('code')) {
        return url.searchParams.get('code');
      }
    }

    return null;
  }

  public async handleCallback(request: Request, options: HandleCallbackOptions): Promise<UserCredentials> {
    const code = await this.getCodeFromRequest(request);

    const redirectUrl = options.onFailureRedirect || this.failedLoginRedirect;
    const searchParams = new URLSearchParams();

    if (!code) {
      console.error('No code found in callback');
      searchParams.set('error', 'no_code');
      throw redirect(redirectUrl.concat('?', searchParams.toString()));
    }

    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('client_id', this.clientCredentials.clientID);
    body.set('client_secret', this.clientCredentials.clientSecret);
    body.set('code', code.toString());
    body.set('redirect_uri', this.callbackURL);

    const response = await fetch(this.auth0Urls.tokenURL, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      body: body.toString()
    });

    if (!response.ok) {
      console.error('Failed to get token from Auth0');
      searchParams.set('error', await this.getErrorReason(response));
      throw redirect(redirectUrl.concat('?', searchParams.toString()));
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

    if (options.onSuccessRedirect) {
      const headers = await saveUserToSession(request, userData, this.session);
      throw redirect(options.onSuccessRedirect, {
        headers: headers
      });
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
    console.log('debug 1');
    try {
      console.log('debug 2');
      credentials = await getCredentials(request, this.session);
    } catch (err) {
      console.log('debug 3');
      console.error('No credentials found');
      throw redirect(this.failedLoginRedirect + '?error=no_credentials');
    }

    try {
      console.log('debug 4');
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

    console.log('Refreshing token', credentials);

    const response = await fetch(this.auth0Urls.tokenURL, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      body: body.toString()
    });
    const searchParams = new URLSearchParams();

    if (!response.ok) {
      console.error('Failed to refresh token from Auth0');
      searchParams.set('error', await this.getErrorReason(response));
      throw redirect(this.failedLoginRedirect.concat('?', searchParams.toString()));
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
    console.log('debug 5');
    const response = await fetch(this.auth0Urls.userProfileUrl, {
      headers: {
        Authorization: `Bearer ${credentials.accessToken}`
      }
    });

    const searchParams = new URLSearchParams();
    console.log('debug 6');
    if (!response.ok) {
      console.error('Failed to get user profile from Auth0');
      searchParams.set('error', await this.getErrorReason(response));
      throw redirect(this.failedLoginRedirect.concat('?', searchParams.toString()));
    }

    const data = (await response.json()) as Auth0UserProfile;
    return transformUserData(data);
  }

  private async getErrorReason(response: Response): Promise<string> {
    if (String(response.status).startsWith('5')) {
      console.error('Auth0 is having a moment');
      return 'auth0_down';
    }

    if (String(response.status).startsWith('4')) {
      // The camelcase comes from Auth0
      // eslint-disable-next-line camelcase
      const responseBody = (await response.json()) as {error: string, error_description: string};
      console.error('Auth0 rejected our request');
      console.error({
        error: responseBody.error,
        description: responseBody.error_description
      });
      return responseBody.error;
    }

    return 'unknown';
  }
}

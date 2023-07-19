/* eslint-disable max-nested-callbacks */
import { redirect } from '@remix-run/server-runtime';
import * as jose from 'jose';
import { afterEach, beforeEach, describe, expect, it, SpyInstance, vi } from 'vitest';
import { getCredentials, saveUserToSession } from './lib/session.js';
import { Auth0RemixServer, Token, SessionStrategy } from './index.js';
import type { Auth0RemixOptions } from './Auth0RemixTypes.js';
import type { AppLoadContext } from '@remix-run/server-runtime';

vi.mock('@remix-run/server-runtime');
vi.mock('./lib/session');
vi.mock('jose');

interface LocalTestContext {
  authOptions: Auth0RemixOptions;
  appLoadContext: AppLoadContext;
}
const redirectError = 'redirect was called';

class JWTExpired extends Error {
  override name = 'JWTExpired';
  code = 'ERR_JWT_EXPIRED';
}

const noop = () => { /* empty */ };

describe('Auth0 Remix Server', () => {
  /* eslint-disable camelcase */
  beforeEach<LocalTestContext>((context) => {
    vi.resetAllMocks();
    vi.setSystemTime(0);
    vi.stubGlobal('fetch', vi.fn());
    vi.mocked(redirect).mockImplementation(() => {
      throw new Error(redirectError as never);
    });
    vi.mocked(jose.createRemoteJWKSet).mockReturnValue('jwkSet' as never);
    context.appLoadContext = {};
    context.authOptions = {
      clientDetails: {
        clientID: 'clientId',
        domain: 'test.domain.com',
        clientSecret: 'clientSecret'
      },
      refreshTokenRotationEnabled: false,
      session: {
        store: {} as never
      },
      callbackURL: 'http://localhost:3000/auth0/callback',
      failedLoginRedirect: '/logout'
    };
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('the authorization process', () => {
    it<LocalTestContext>('redirects to the authorization endpoint', ({ authOptions }) => {
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize()).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).toMatchSnapshot();
    });

    it<LocalTestContext>('uses post when post is not set', ({ authOptions }) => {
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize()).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).toContain('response_mode=form_post');
    });

    it<LocalTestContext>('uses post when post is set to true', ({ authOptions }) => {
      authOptions.clientDetails.usePost = true;
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize()).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).toContain('response_mode=form_post');
    });

    it<LocalTestContext>('uses get when post is set to false', ({ authOptions }) => {
      authOptions.clientDetails.usePost = false;
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize()).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).not.toContain('response_mode=form_post');
    });

    it<LocalTestContext>('forces the login if asked', ({ authOptions }) => {
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize({
        forceLogin: true
      })).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).toContain('prompt=login');
    });

    it<LocalTestContext>('does silent auth if asked', ({ authOptions }) => {
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize({
        silentAuth: true
      })).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).toContain('prompt=none');
    });

    it<LocalTestContext>('works correctly when both are asked', ({ authOptions }) => {
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize({
        forceLogin: true,
        forceSignup: true
      })).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).toContain('prompt=login');
    });

    it<LocalTestContext>('prioritizes the silent login over the force', ({ authOptions }) => {
      // this is for the not-typescript case where both can be passed
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize({
        forceLogin: true,
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        silentAuth: true
      })).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).toContain('prompt=none');
      expect(redirectUrl).not.toContain('prompt=login');
    });

    it<LocalTestContext>('forces the signup if asked', ({ authOptions }) => {
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize({
        forceSignup: true
      })).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).toMatchSnapshot();
    });

    it<LocalTestContext>('adds the connection when needed', ({ authOptions }) => {
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize({
        connection: 'google'
      })).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).toContain('connection=google');
    });

    it<LocalTestContext>('adds the organisation if needed', ({ authOptions }) => {
      authOptions.clientDetails.organization = 'test-org';
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize()).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).toMatchSnapshot();
    });

    it<LocalTestContext>('adds custom callback url parameters', ({ authOptions }) => {
      const authorizer = new Auth0RemixServer(authOptions);

      expect(() => authorizer.authorize({
        callbackParams: {
          test1: 'testA',
          test2: 'testB',
          test3: 'testC'
        }
      })).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      expect(redirectUrl).toContain('test1%3DtestA');
      expect(redirectUrl).toContain('test2%3DtestB');
      expect(redirectUrl).toContain('test3%3DtestC');
      expect(redirectUrl).toMatchSnapshot();
    });
  });

  describe('handling the callback token exchange', () => {
    describe('when there is no code in the exchange', () => {
      it<LocalTestContext>('redirects to the failed login url', async ({ authOptions }) => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
        const authorizer = new Auth0RemixServer(authOptions);
        const request = new Request('https://it-doesnt-matter.com', {
          method: 'GET'
        });

        await expect(authorizer.handleCallback(request, {})).rejects.toThrowError(redirectError); // a redirect happened

        const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
        expect(redirectUrl).toEqual(authOptions.failedLoginRedirect + '?error=no_code');

        expect(consoleSpy).toHaveBeenCalledWith('No code found in callback');
      });

      it<LocalTestContext>('redirects to the overridden failed login url', async ({ authOptions }) => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
        const authorizer = new Auth0RemixServer(authOptions);
        const request = new Request('https://it-doesnt-matter.com', {
          method: 'POST',
          body: new FormData()
        });

        await expect(authorizer.handleCallback(request, {
          onFailureRedirect: '/redirected'
        })).rejects.toThrowError(redirectError); // a redirect happened

        const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
        expect(redirectUrl).toEqual('/redirected?error=no_code');

        expect(consoleSpy).toHaveBeenCalledWith('No code found in callback');
      });
    });

    describe('when there is a code in the exchange as a POST', () => {
      let consoleSpy: SpyInstance;
      let authorizer: Auth0RemixServer;
      let request: Request;

      beforeEach<LocalTestContext>(({ authOptions }) => {
        consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
        authorizer = new Auth0RemixServer(authOptions);
        const formData = new FormData();
        formData.append('code', 'test-code');

        request = new Request('https://it-doesnt-matter.com', {
          method: 'POST',
          body: formData
        });
      });

      it<LocalTestContext>('redirects to the failed login url if the token exchange fails', async ({ authOptions }) => {
        vi.mocked(fetch).mockResolvedValue({
          ok: false, // return a non-ok response
          status: 400,
          json: async () => ({
            error: 'invalid_grant',
            error_description: 'Invalid authorization code'
          })
        } as never);

        await expect(authorizer.handleCallback(request, {})).rejects.toThrowError(redirectError); // a redirect happened

        const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
        expect(redirectUrl).toEqual(authOptions.failedLoginRedirect + '?error=invalid_grant');

        const fetchArgs = vi.mocked(fetch).mock.calls[0];
        expect(fetchArgs[0]).toMatchInlineSnapshot('"https://test.domain.com/oauth/token"');
        expect(fetchArgs[1]).toMatchSnapshot();
        expect(consoleSpy).toHaveBeenCalledWith('Failed to get token from Auth0');
      });

      it<LocalTestContext>('redirects to the overridden failed login url if the token exchange fails', async () => {
        vi.mocked(fetch).mockResolvedValue({
          ok: false, // return a non-ok response
          status: 401,
          json: async () => ({
            error: 'unauthorized',
            error_description: 'Invalid authorization code again'
          })
        } as never);

        await expect(authorizer.handleCallback(request, {
          onFailureRedirect: '/redirected'
        })).rejects.toThrowError(redirectError); // a redirect happened

        const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
        expect(redirectUrl).toEqual('/redirected?error=unauthorized');
      });

      it<LocalTestContext>('handles auth0 failures', async () => {
        vi.mocked(fetch).mockResolvedValue({
          ok: false, // return a non-ok response
          status: 500
        } as never);

        await expect(authorizer.handleCallback(request, {
          onFailureRedirect: '/redirected'
        })).rejects.toThrowError(redirectError); // a redirect happened

        const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
        expect(redirectUrl).toEqual('/redirected?error=auth0_down');
      });

      it<LocalTestContext>('handles unknown failures', async ({ authOptions }) => {
        vi.mocked(fetch).mockResolvedValue({
          ok: false // return a non-ok response
        } as never);

        await expect(authorizer.handleCallback(request, {})).rejects.toThrowError(redirectError); // a redirect happened

        const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
        expect(redirectUrl).toEqual(authOptions.failedLoginRedirect + '?error=unknown');
      });

      describe('and there is no success url', () => {
        it('returns the user profile', async () => {
          const auth0Response = {
            access_token: 'test-access-token',
            id_token: 'test-id-token',
            expires_in: 30,
            refresh_token: 'test-refresh-token'
          };
          vi.mocked(fetch).mockResolvedValue({
            ok: true, // return a non-ok response
            json: () => Promise.resolve(auth0Response)
          } as never);

          const actual = await authorizer.handleCallback(request, {});

          expect(actual).toMatchInlineSnapshot(`
            {
              "accessToken": "test-access-token",
              "expiresAt": 30000,
              "expiresIn": 30,
              "lastRefreshed": 0,
            }
          `);
        });

        it<LocalTestContext>('includes the refresh token if the rotation is set', async ({ authOptions }) => {
          authOptions.refreshTokenRotationEnabled = true;
          authorizer = new Auth0RemixServer(authOptions);
          const auth0Response = {
            access_token: 'test-access-token2',
            id_token: 'test-id-token2',
            expires_in: 600,
            refresh_token: 'test-refresh-token2'
          };

          vi.mocked(fetch).mockResolvedValue({
            ok: true, // return a non-ok response
            json: () => Promise.resolve(auth0Response)
          } as never);

          const actual = await authorizer.handleCallback(request, {});

          expect(actual).toMatchInlineSnapshot(`
            {
              "accessToken": "test-access-token2",
              "expiresAt": 600000,
              "expiresIn": 600,
              "lastRefreshed": 0,
              "refreshToken": "test-refresh-token2",
            }
          `);
        });
      });

      describe('and there is a success url', () => {
        it<LocalTestContext>('redirects to the success url', async ({ authOptions }) => {
          authOptions.session = {
            store: 'sessionStore',
            key: 'sessionKey',
            strategy: SessionStrategy.Server
          } as never;
          const auth0Response = {
            access_token: 'test-access-token3',
            id_token: 'test-id-token3',
            expires_in: 300,
            refresh_token: 'test-refresh-token3'
          };
          vi.mocked(fetch).mockResolvedValue({
            ok: true, // return a non-ok response
            json: () => Promise.resolve(auth0Response)
          } as never);

          vi.mocked(saveUserToSession).mockResolvedValue({
            'some-cookie': 'data'
          });

          const authorizer = new Auth0RemixServer(authOptions);
          await expect(authorizer.handleCallback(request, {
            onSuccessRedirect: 'https://success-login-redirect.com'
          })).rejects.toThrowError(redirectError); // a redirect happened

          const saveUserToSessionArgs = vi.mocked(saveUserToSession).mock.calls[0];
          expect(saveUserToSessionArgs[0]).toBe(request);
          expect(saveUserToSessionArgs[2]).toEqual(authOptions.session);
          expect(saveUserToSessionArgs[1]).toMatchInlineSnapshot(`
            {
              "accessToken": "test-access-token3",
              "expiresAt": 300000,
              "expiresIn": 300,
              "lastRefreshed": 0,
            }
          `);

          const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
          expect(redirectUrl).toEqual('https://success-login-redirect.com');

          const redirectInit = vi.mocked(redirect).mock.calls[0][1];
          expect(redirectInit).toMatchInlineSnapshot(`
            {
              "headers": {
                "some-cookie": "data",
              },
            }
          `);

        });

        it<LocalTestContext>('calls the token escape hatch', async ({ authOptions }) => {
          const escapeHatch = vi.fn();

          authOptions.session = {
            store: 'sessionStore',
            key: 'sessionKey'
          } as never;
          authOptions.credentialsCallback = escapeHatch;
          const auth0Response = {
            access_token: 'test-access-token4',
            id_token: 'test-id-token4',
            expires_in: 600,
            refresh_token: 'test-refresh-token4'
          };

          vi.mocked(fetch).mockResolvedValue({
            ok: true, // return a non-ok response
            json: () => Promise.resolve(auth0Response)
          } as never);

          vi.mocked(saveUserToSession).mockResolvedValue({
            'some-cookie': 'data'
          });

          const authorizer = new Auth0RemixServer(authOptions);
          await expect(authorizer.handleCallback(request, {
            onSuccessRedirect: 'https://success-login-redirect.com'
          })).rejects.toThrowError(redirectError); // a redirect happened

          expect(escapeHatch).toHaveBeenCalledWith({
            accessToken: 'test-access-token4',
            refreshToken: 'test-refresh-token4',
            expiresIn: 600,
            lastRefreshed: 0,
            expiresAt: 600000
          });
        });
      });
    });

    describe('when there is a code in the exchange as a GET', () => {
      let consoleSpy: SpyInstance;
      let authorizer: Auth0RemixServer;
      let request: Request;

      beforeEach<LocalTestContext>(({ authOptions }) => {
        consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
        authorizer = new Auth0RemixServer(authOptions);

        request = new Request('https://it-doesnt-matter.com?code=test-code', {
          method: 'GET'
        });
      });

      it<LocalTestContext>('redirects to the failed login url if the token exchange fails', async ({ authOptions }) => {
        vi.mocked(fetch).mockResolvedValue({
          ok: false, // return a non-ok response
          status: 400,
          json: async () => ({
            error: 'invalid_grant',
            error_description: 'Invalid authorization code'
          })
        } as never);

        await expect(authorizer.handleCallback(request, {})).rejects.toThrowError(redirectError); // a redirect happened

        const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
        expect(redirectUrl).toEqual(authOptions.failedLoginRedirect + '?error=invalid_grant');

        const fetchArgs = vi.mocked(fetch).mock.calls[0];
        expect(fetchArgs[0]).toMatchInlineSnapshot('"https://test.domain.com/oauth/token"');
        expect(fetchArgs[1]).toMatchSnapshot();
        expect(consoleSpy).toHaveBeenCalledWith('Failed to get token from Auth0');
      });

      it<LocalTestContext>('redirects to the overridden failed login url if the token exchange fails', async () => {
        vi.mocked(fetch).mockResolvedValue({
          ok: false, // return a non-ok response
          status: 401,
          json: async () => ({
            error: 'unauthorized',
            error_description: 'Invalid authorization code again'
          })
        } as never);

        await expect(authorizer.handleCallback(request, {
          onFailureRedirect: '/redirected'
        })).rejects.toThrowError(redirectError); // a redirect happened

        const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
        expect(redirectUrl).toEqual('/redirected?error=unauthorized');
      });

      it<LocalTestContext>('handles auth0 failures', async () => {
        vi.mocked(fetch).mockResolvedValue({
          ok: false, // return a non-ok response
          status: 500
        } as never);

        await expect(authorizer.handleCallback(request, {
          onFailureRedirect: '/redirected'
        })).rejects.toThrowError(redirectError); // a redirect happened

        const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
        expect(redirectUrl).toEqual('/redirected?error=auth0_down');
      });

      it<LocalTestContext>('handles unknown failures', async ({ authOptions }) => {
        vi.mocked(fetch).mockResolvedValue({
          ok: false // return a non-ok response
        } as never);

        await expect(authorizer.handleCallback(request, {})).rejects.toThrowError(redirectError); // a redirect happened

        const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
        expect(redirectUrl).toEqual(authOptions.failedLoginRedirect + '?error=unknown');
      });

      describe('and there is no success url', () => {
        it('returns the user profile', async () => {
          const auth0Response = {
            access_token: 'test-access-token',
            id_token: 'test-id-token',
            expires_in: 30,
            refresh_token: 'test-refresh-token'
          };
          vi.mocked(fetch).mockResolvedValue({
            ok: true, // return a non-ok response
            json: () => Promise.resolve(auth0Response)
          } as never);

          const actual = await authorizer.handleCallback(request, {});

          expect(actual).toMatchInlineSnapshot(`
            {
              "accessToken": "test-access-token",
              "expiresAt": 30000,
              "expiresIn": 30,
              "lastRefreshed": 0,
            }
          `);
        });

        it<LocalTestContext>('includes the refresh token if the rotation is set', async ({ authOptions }) => {
          authOptions.refreshTokenRotationEnabled = true;
          authorizer = new Auth0RemixServer(authOptions);
          const auth0Response = {
            access_token: 'test-access-token2',
            id_token: 'test-id-token2',
            expires_in: 600,
            refresh_token: 'test-refresh-token2'
          };

          vi.mocked(fetch).mockResolvedValue({
            ok: true, // return a non-ok response
            json: () => Promise.resolve(auth0Response)
          } as never);

          const actual = await authorizer.handleCallback(request, {});

          expect(actual).toMatchInlineSnapshot(`
            {
              "accessToken": "test-access-token2",
              "expiresAt": 600000,
              "expiresIn": 600,
              "lastRefreshed": 0,
              "refreshToken": "test-refresh-token2",
            }
          `);
        });
      });

      describe('and there is a success url', () => {
        it<LocalTestContext>('redirects to the success url', async ({ authOptions }) => {
          authOptions.session = {
            store: 'sessionStore',
            key: 'sessionKey',
            strategy: SessionStrategy.Browser
          } as never;
          const auth0Response = {
            access_token: 'test-access-token3',
            id_token: 'test-id-token3',
            expires_in: 300,
            refresh_token: 'test-refresh-token3'
          };
          vi.mocked(fetch).mockResolvedValue({
            ok: true, // return a non-ok response
            json: () => Promise.resolve(auth0Response)
          } as never);

          vi.mocked(saveUserToSession).mockResolvedValue({
            'some-cookie': 'data'
          });

          const authorizer = new Auth0RemixServer(authOptions);
          await expect(authorizer.handleCallback(request, {
            onSuccessRedirect: 'https://success-login-redirect.com'
          })).rejects.toThrowError(redirectError); // a redirect happened

          const saveUserToSessionArgs = vi.mocked(saveUserToSession).mock.calls[0];
          expect(saveUserToSessionArgs[0]).toBe(request);
          expect(saveUserToSessionArgs[2]).toEqual(authOptions.session);
          expect(saveUserToSessionArgs[1]).toMatchInlineSnapshot(`
            {
              "accessToken": "test-access-token3",
              "expiresAt": 300000,
              "expiresIn": 300,
              "lastRefreshed": 0,
            }
          `);

          const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
          expect(redirectUrl).toEqual('https://success-login-redirect.com');

          const redirectInit = vi.mocked(redirect).mock.calls[0][1];
          expect(redirectInit).toMatchInlineSnapshot(`
            {
              "headers": {
                "some-cookie": "data",
              },
            }
          `);

        });

        it<LocalTestContext>('calls the token escape hatch', async ({ authOptions }) => {
          const escapeHatch = vi.fn();

          authOptions.session = {
            store: 'sessionStore',
            key: 'sessionKey'
          } as never;
          authOptions.credentialsCallback = escapeHatch;
          const auth0Response = {
            access_token: 'test-access-token4',
            id_token: 'test-id-token4',
            expires_in: 600,
            refresh_token: 'test-refresh-token4'
          };

          vi.mocked(fetch).mockResolvedValue({
            ok: true, // return a non-ok response
            json: () => Promise.resolve(auth0Response)
          } as never);

          vi.mocked(saveUserToSession).mockResolvedValue({
            'some-cookie': 'data'
          });

          const authorizer = new Auth0RemixServer(authOptions);
          await expect(authorizer.handleCallback(request, {
            onSuccessRedirect: 'https://success-login-redirect.com'
          })).rejects.toThrowError(redirectError); // a redirect happened

          expect(escapeHatch).toHaveBeenCalledWith({
            accessToken: 'test-access-token4',
            refreshToken: 'test-refresh-token4',
            expiresIn: 600,
            lastRefreshed: 0,
            expiresAt: 600000
          });
        });
      });
    });
  });

  describe('logging out', () => {
    it<LocalTestContext>('calls the correct url', ({ authOptions }) => {
      const authorizer = new Auth0RemixServer(authOptions);
      const redirectTo = 'http://localhost:3000/logout';

      expect(() => authorizer.logout(redirectTo)).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      const requestInit = vi.mocked(redirect).mock.calls[0][1];
      expect(redirectUrl).toMatchSnapshot();
      expect(requestInit).toEqual({ headers: {} });
    });

    it<LocalTestContext>('includes the headers supplied', ({ authOptions }) => {
      const authorizer = new Auth0RemixServer(authOptions);
      const redirectTo = 'http://localhost:3000/logout-with-headers';
      const headers = {
        'X-Test-Header': 'test',
        'X-Test-Header-2': 'test2'
      };

      expect(() => authorizer.logout(redirectTo, headers)).toThrowError(redirectError); // a redirect happened

      const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
      const requestInit = vi.mocked(redirect).mock.calls[0][1];
      expect(redirectUrl).toMatchSnapshot();
      expect(requestInit).toEqual({ headers: headers });
    });
  });

  describe('getting the user', () => {
    describe('when there are no credentials returned', () => {
      it<LocalTestContext>('redirects to the failed login url', async ({ authOptions }) => {
        vi.mocked(getCredentials).mockRejectedValue(new Error('Credentials not found'));

        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(noop);

        const request = new Request('https://it-doesnt-matter.com');
        const context: AppLoadContext = {};

        const authorizer = new Auth0RemixServer(authOptions);
        await expect(authorizer.getUser(request, context)).rejects.toThrowError(redirectError); // a redirect happened
        const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
        expect(redirectUrl).toMatchSnapshot();
        expect(consoleSpy).toHaveBeenCalledWith('No credentials found');
      });
    });
    describe('when the access token is valid', () => {
      beforeEach(() => {
        vi.mocked(getCredentials).mockResolvedValueOnce({
          accessToken: 'test-access-token',
          expiresAt: 66669420
        } as never);
        vi.mocked(jose.jwtVerify).mockResolvedValue({} as never);
      });

      describe('and there is a user cache in place', () => {
        beforeEach<LocalTestContext>((context) => {
          context.authOptions.profileCacheGet = vi.fn();
        });

        it<LocalTestContext>('returns the cached result', async ({ authOptions }) => {
          vi.mocked(authOptions.profileCacheGet!).mockResolvedValue({
            email: 'test@email.here'
          } as never);

          const request = new Request('https://it-doesnt-matter.com');

          const authorizer = new Auth0RemixServer(authOptions);
          const actual = await authorizer.getUser(request, {});

          expect(actual.email).toEqual('test@email.here');
          expect(authOptions.profileCacheGet).toHaveBeenCalledWith('test-access-token');
        });

        describe('when the cache misses', () => {
          it<LocalTestContext>('calls out to auth0', async ({ authOptions }) => {
            authOptions.profileCacheSet = vi.fn();
            vi.mocked(authOptions.profileCacheGet!).mockRejectedValueOnce(new Error('Cache miss'));

            authOptions.session = {
              store: 'sessionStore',
              key: 'sessionKey',
              strategy: SessionStrategy.Browser
            } as never;

            const user = {
              name: 'test-user',
              first_name: 'test-first-name'
            };

            vi.mocked(fetch).mockResolvedValue({
              ok: true,
              json: () => Promise.resolve(user)
            } as never);

            const request = new Request('https://it-doesnt-matter.com');

            const authorizer = new Auth0RemixServer(authOptions);
            const actual = await authorizer.getUser(request, {});

            expect(actual.firstName).toEqual('test-first-name');
            expect(actual.name).toEqual('test-user');

            const fetchParams = vi.mocked(fetch).mock.calls[0];
            expect(fetchParams[0]).toEqual('https://test.domain.com/userinfo');

            expect(authOptions.profileCacheSet).toHaveBeenCalledWith('test-access-token', {
              firstName: 'test-first-name',
              name: 'test-user'
            }, 66669420);
          });
        });
      });

      describe('and the user profile fetch succeeds', () => {
        it<LocalTestContext>('returns the user', async ({ authOptions }) => {
          authOptions.session = {
            store: 'sessionStore',
            key: 'sessionKey',
            strategy: SessionStrategy.Browser
          } as never;

          const user = {
            name: 'test-user',
            first_name: 'test-first-name'
          };

          vi.mocked(fetch).mockResolvedValue({
            ok: true,
            json: () => Promise.resolve(user)
          } as never);

          const request = new Request('https://it-doesnt-matter.com');

          const authorizer = new Auth0RemixServer(authOptions);
          const actual = await authorizer.getUser(request, {});

          expect(actual).toMatchInlineSnapshot(`
            {
              "firstName": "test-first-name",
              "name": "test-user",
            }
          `);

          const jwtVerifyParams = vi.mocked(jose.jwtVerify).mock.calls[0];
          expect(jwtVerifyParams[0]).toEqual('test-access-token');
          expect(jwtVerifyParams[1]).toEqual('jwkSet');
          expect(jwtVerifyParams[2]).toMatchInlineSnapshot(`
            {
              "audience": "https://test.domain.com/api/v2/",
              "issuer": "https://test.domain.com/",
            }
          `);

          const fetchParams = vi.mocked(fetch).mock.calls[0];
          expect(fetchParams[0]).toEqual('https://test.domain.com/userinfo');
          expect(fetchParams[1]).toMatchInlineSnapshot(`
            {
              "headers": {
                "Authorization": "Bearer test-access-token",
              },
            }
          `);

          expect(getCredentials).toHaveBeenCalledWith(request, authOptions.session);
        });
      });

      describe('and the user profile fetch fails', () => {
        it<LocalTestContext>('redirects to the failed url', async ({ authOptions }) => {
          authOptions.session = {
            store: 'sessionStore',
            key: 'sessionKey'
          } as never;

          vi.mocked(fetch).mockResolvedValue({
            ok: false,
            status: 400,
            json: () => Promise.resolve({ error: 'test-error' })
          } as never);

          const consoleSpy = vi.spyOn(console, 'error').mockImplementation(noop);

          const request = new Request('https://it-doesnt-matter.com');

          const authorizer = new Auth0RemixServer(authOptions);
          await expect(authorizer.getUser(request, {})).rejects.toThrowError(redirectError); // a redirect happened
          expect(consoleSpy).toHaveBeenCalledWith('Failed to get user profile from Auth0');
          const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
          expect(redirectUrl).toMatchSnapshot();
          expect(redirectUrl).toContain('error=test-error');
        });
      });
    });

    describe('when the token validation fails', () => {
      it<LocalTestContext>('redirects to the failed login url', async ({ authOptions }) => {
        vi.mocked(getCredentials).mockResolvedValueOnce({} as never);
        vi.mocked(jose.jwtVerify).mockRejectedValue(new Error('test-error'));

        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(noop);

        const request = new Request('https://it-doesnt-matter.com');
        const context: AppLoadContext = {};

        const authorizer = new Auth0RemixServer(authOptions);
        await expect(authorizer.getUser(request, context)).rejects.toThrowError(redirectError); // a redirect happened
        expect(consoleSpy).toHaveBeenCalledWith('Failed to verify JWT', new Error('test-error'));
      });
    });

    describe('when the token is expired', () => {
      beforeEach(() => {
        vi.mocked(jose.jwtVerify).mockRejectedValueOnce(new JWTExpired('test-error'));
      });

      describe('and there is no other loader refreshing the token', () => {
        beforeEach<LocalTestContext>((context) => {
          delete context.appLoadContext.refresh;
        });
        describe('and there is no refresh token', () => {
          beforeEach(() => {
            vi.mocked(getCredentials).mockResolvedValue({} as never);
          });

          it<LocalTestContext>('redirects to the failed login url', async ({ authOptions, appLoadContext }) => {
            const consoleSpy = vi.spyOn(console, 'error').mockImplementation(noop);
            const request = new Request('https://it-doesnt-matter.com');

            const authorizer = new Auth0RemixServer(authOptions);
            await expect(authorizer.getUser(request, appLoadContext)).rejects.toThrowError(redirectError); // a redirect happened
            expect(consoleSpy).toHaveBeenCalledWith('No refresh token found within the credentials.');
          });
        });

        describe('and there is a refresh token', () => {
          beforeEach(() => {
            vi.mocked(getCredentials).mockResolvedValue({
              refreshToken: 'test-refresh-token'
            } as never);
          });

          it<LocalTestContext>('redirects to the failed login url when the refresh fails', async ({ authOptions, appLoadContext }) => {
            vi.mocked(fetch).mockResolvedValue({
              ok: false,
              status: 400,
              json: () => Promise.resolve({ error: 'test-error2' })
            } as never);
            const consoleSpy = vi.spyOn(console, 'error').mockImplementation(noop);
            const request = new Request('https://it-doesnt-matter.com');

            const authorizer = new Auth0RemixServer(authOptions);
            await expect(authorizer.getUser(request, appLoadContext)).rejects.toThrowError(redirectError); // a redirect happened
            expect(consoleSpy).toHaveBeenCalledWith('Failed to refresh token from Auth0');
            const redirectUrl = vi.mocked(redirect).mock.calls[0][0];
            expect(redirectUrl).toMatchSnapshot();
            expect(redirectUrl).toContain('error=test-error2');
          });

          it<LocalTestContext>('returns the correct credentials with the rotation off', async ({ authOptions, appLoadContext }) => {
            vi.mocked(fetch).mockResolvedValue({
              ok: true,
              json: () => Promise.resolve({
                access_token: 'new-access-token',
                refresh_token: 'new-refresh-token',
                expires_in: 1000
              })
            } as never);

            vi.mocked(saveUserToSession).mockResolvedValueOnce({
              'a-header': 'a-value'
            } as never);

            const request = new Request('https://it-doesnt-matter.com');
            authOptions.refreshTokenRotationEnabled = false;
            authOptions.session = {
              store: 'sessionStore',
              key: 'sessionKey',
              strategy: SessionStrategy.Browser
            } as never;
            const authorizer = new Auth0RemixServer(authOptions);

            /** Execute the test */
            await expect(authorizer.getUser(request, appLoadContext)).rejects.toThrowError(redirectError); // a redirect happened

            expect(appLoadContext.refresh).toBeDefined(); // it sets the context properly

            /**
             * It calls the refresh endpoint with the correct parameters
             */
            const fetchCall = vi.mocked(fetch).mock.calls[0];
            expect(fetchCall[0]).toEqual('https://test.domain.com/oauth/token');
            expect(fetchCall[1]).toMatchInlineSnapshot(`
              {
                "body": "grant_type=refresh_token&client_id=clientId&client_secret=clientSecret&refresh_token=test-refresh-token",
                "headers": {
                  "content-type": "application/x-www-form-urlencoded",
                },
                "method": "POST",
              }
            `);

            /**
             * It updates the session correctly
             * And does not contain the refresh token
             */
            const saveUserToSessionCall = vi.mocked(saveUserToSession).mock.calls[0];
            expect(saveUserToSessionCall[0]).toEqual(request);
            expect(saveUserToSessionCall[1]).toMatchInlineSnapshot(`
              {
                "accessToken": "new-access-token",
                "expiresAt": 1000000,
                "expiresIn": 1000,
                "lastRefreshed": 0,
              }
            `);
            expect(Object.keys(saveUserToSessionCall[1])).not.toContain('refreshToken');
            expect(saveUserToSessionCall[2]).toEqual(authOptions.session);

            /**
             * It redirects to the correct url with values from the sessionSave
             */
            expect(redirect).toHaveBeenCalledWith('https://it-doesnt-matter.com/', {
              headers: {
                'a-header': 'a-value'
              }
            });

          });

          it<LocalTestContext>('returns the correct credentials with the rotation on', async ({ authOptions, appLoadContext }) => {
            vi.mocked(fetch).mockResolvedValue({
              ok: true,
              json: () => Promise.resolve({
                access_token: 'new-access-token2',
                refresh_token: 'new-refresh-token2',
                expires_in: 3000
              })
            } as never);

            vi.mocked(saveUserToSession).mockResolvedValueOnce({
              'a-header2': 'a-value2'
            } as never);

            const request = new Request('https://it-doesnt-matter.com');
            authOptions.refreshTokenRotationEnabled = true;
            const authorizer = new Auth0RemixServer(authOptions);

            /** Execute the test */
            await expect(authorizer.getUser(request, appLoadContext)).rejects.toThrowError(redirectError); // a redirect happened

            expect(appLoadContext.refresh).toBeDefined(); // it sets the context properly

            /**
             * It updates the session correctly
             * And it contains the refresh token
             */
            const saveUserToSessionCall = vi.mocked(saveUserToSession).mock.calls[0];
            expect(saveUserToSessionCall[1]).toMatchInlineSnapshot(`
              {
                "accessToken": "new-access-token2",
                "expiresAt": 3000000,
                "expiresIn": 3000,
                "lastRefreshed": 0,
                "refreshToken": "new-refresh-token2",
              }
            `);
            expect(Object.keys(saveUserToSessionCall[1])).toContain('refreshToken');

          });

          it<LocalTestContext>('does not redirect with the server strategy enabled', async ({ authOptions, appLoadContext }) => {
            vi.mocked(jose.jwtVerify).mockResolvedValueOnce({} as never);
            vi.mocked(fetch).mockResolvedValueOnce({
              ok: true,
              json: () => Promise.resolve({
                access_token: 'new-access-token2',
                refresh_token: 'new-refresh-token2',
                expires_in: 3000
              })
            } as never);

            const user = {
              name: 'test-user',
              first_name: 'test-first-name'
            };

            vi.mocked(fetch).mockResolvedValueOnce({
              ok: true,
              json: () => Promise.resolve(user)
            } as never);

            vi.mocked(saveUserToSession).mockResolvedValueOnce({
              'a-header2': 'a-value2'
            } as never);

            const request = new Request('https://it-doesnt-matter.com');
            authOptions.refreshTokenRotationEnabled = true;
            authOptions.session.strategy = SessionStrategy.Server;
            const authorizer = new Auth0RemixServer(authOptions);

            /** Execute the test */
            const actual = await authorizer.getUser(request, appLoadContext);

            expect(appLoadContext.refresh).toBeDefined(); // it sets the context properly

            /**
             * It updates the session correctly
             * And it contains the refresh token
             */
            const saveUserToSessionCall = vi.mocked(saveUserToSession).mock.calls[0];
            expect(saveUserToSessionCall[1]).toEqual(
              {
                'accessToken': 'new-access-token2',
                'expiresAt': 3000000,
                'expiresIn': 3000,
                'lastRefreshed': 0,
                'refreshToken': 'new-refresh-token2'
              }
            );
            expect(Object.keys(saveUserToSessionCall[1])).toContain('refreshToken');
            expect(actual).toEqual({
              'firstName': 'test-first-name',
              'name': 'test-user'
            });

          });

          it<LocalTestContext>('calls the credentials escape hatch callback', async ({ authOptions, appLoadContext }) => {
            const escapeHatch = vi.fn();
            vi.mocked(fetch).mockResolvedValue({
              ok: true,
              json: () => Promise.resolve({
                access_token: 'new-access-token3',
                refresh_token: 'new-refresh-token3',
                expires_in: 3000
              })
            } as never);

            vi.mocked(saveUserToSession).mockResolvedValueOnce({
              'a-header2': 'a-value2'
            } as never);

            const request = new Request('https://it-doesnt-matter.com');
            authOptions.refreshTokenRotationEnabled = true;
            authOptions.credentialsCallback = escapeHatch;
            const authorizer = new Auth0RemixServer(authOptions);

            /** Execute the test */
            await expect(authorizer.getUser(request, appLoadContext)).rejects.toThrowError(redirectError); // a redirect happened

            expect(escapeHatch).toHaveBeenCalledWith({
              accessToken: 'new-access-token3',
              refreshToken: 'new-refresh-token3',
              expiresIn: 3000,
              expiresAt: 3000000,
              lastRefreshed: 0
            });

          });

          it<LocalTestContext>('returns the user when there is an ongoing refresh', async ({ authOptions }) => {

            vi.mocked(jose.jwtVerify).mockResolvedValueOnce({} as never); // this will be the second call after the one in the beforeEach

            vi.mocked(fetch).mockResolvedValue({
              ok: true,
              json: () => Promise.resolve({
                name: 'test-user'
              })
            } as never);

            const request = new Request('https://it-doesnt-matter.com');

            const authorizer = new Auth0RemixServer(authOptions);
            const actual = await authorizer.getUser(request, {
              refresh: Promise.resolve()
            });

            expect(actual).toEqual({
              name: 'test-user'
            });
          });
        });
      });
    });
  });

  describe('the verification functions', () => {
    it<LocalTestContext>('can successfully verify an access token', async ({ authOptions }) => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({} as never);
      authOptions.clientDetails.domain = 'test.domain.com';
      authOptions.clientDetails.audience = 'verification-audience';
      const authorizer = new Auth0RemixServer(authOptions);
      const actual = await authorizer.isValid('test-token', Token.ACCESS);

      expect(actual).toBeTruthy();

      expect(jose.jwtVerify).toHaveBeenCalledWith('test-token', 'jwkSet', {
        issuer: 'https://test.domain.com/',
        audience: 'verification-audience'
      });
    });

    it<LocalTestContext>('can report a failed access token validity', async ({ authOptions }) => {
      vi.mocked(jose.jwtVerify).mockRejectedValueOnce({} as never);
      authOptions.clientDetails.domain = 'test.domain.com';
      authOptions.clientDetails.audience = 'verification-audience';
      const authorizer = new Auth0RemixServer(authOptions);
      const actual = await authorizer.isValid('test-token', Token.ACCESS);

      expect(actual).toBeFalsy();

      expect(jose.jwtVerify).toHaveBeenCalledWith('test-token', 'jwkSet', {
        issuer: 'https://test.domain.com/',
        audience: 'verification-audience'
      });
    });

    it<LocalTestContext>('can successfully verify an id token', async ({ authOptions }) => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({} as never);
      authOptions.clientDetails.domain = 'test.domain.com';
      authOptions.clientDetails.clientID = 'verification-clientID';
      const authorizer = new Auth0RemixServer(authOptions);
      const actual = await authorizer.isValid('test-token', Token.ID);

      expect(actual).toBeTruthy();

      expect(jose.jwtVerify).toHaveBeenCalledWith('test-token', 'jwkSet', {
        issuer: 'https://test.domain.com/',
        audience: 'verification-clientID'
      });
    });

    it<LocalTestContext>('can report a failed id token validity', async ({ authOptions }) => {
      vi.mocked(jose.jwtVerify).mockRejectedValueOnce({} as never);
      authOptions.clientDetails.domain = 'test.domain.com';
      authOptions.clientDetails.clientID = 'verification-clientID';
      const authorizer = new Auth0RemixServer(authOptions);
      const actual = await authorizer.isValid('test-token', Token.ID);

      expect(actual).toBeFalsy();

      expect(jose.jwtVerify).toHaveBeenCalledWith('test-token', 'jwkSet', {
        issuer: 'https://test.domain.com/',
        audience: 'verification-clientID'
      });
    });

    it<LocalTestContext>('can report the correct error when the token is invalid', async ({ authOptions }) => {

      vi.mocked(jose.jwtVerify).mockRejectedValueOnce(new Error('invalid token'));
      const authorizer = new Auth0RemixServer(authOptions);

      await expect(authorizer.verifyToken('test-token', Token.ID)).rejects.toThrowError('invalid token');

    });
  });

  describe('The secure decoding of the tokens', () => {
    it<LocalTestContext>('can report the correct error when the token is not valid', async ({ authOptions }) => {

      vi.mocked(jose.jwtVerify).mockRejectedValueOnce(new Error('another invalid token'));
      const authorizer = new Auth0RemixServer(authOptions);

      await expect(authorizer.decodeToken('test-token', Token.ID)).rejects.toThrowError('another invalid token');
    });

    it<LocalTestContext>('can successfully decode an access token', async ({ authOptions }) => {
      authOptions.clientDetails.domain = 'test.domain.com';
      authOptions.clientDetails.audience = 'verification-audience';

      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: {
          sub: 'test-subject',
          aud: 'verification-audience'
        }
      } as never);

      const authorizer = new Auth0RemixServer(authOptions);
      const actual = await authorizer.decodeToken('test-token', Token.ACCESS);

      expect(actual).toEqual({
        sub: 'test-subject',
        aud: 'verification-audience'
      });

      expect(jose.jwtVerify).toHaveBeenCalledWith('test-token', 'jwkSet', {
        issuer: 'https://test.domain.com/',
        audience: 'verification-audience'
      });
    });

    it<LocalTestContext>('can successfully decode an ID token', async ({ authOptions }) => {
      authOptions.clientDetails.domain = 'test.domain.com';
      authOptions.clientDetails.clientID = 'verification-clientID';

      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: {
          sub: 'test-subject',
          name: 'test-name'
        }
      } as never);

      const authorizer = new Auth0RemixServer(authOptions);
      const actual = await authorizer.decodeToken('test-token', Token.ID);

      expect(actual).toEqual({
        sub: 'test-subject',
        name: 'test-name'
      });

      expect(jose.jwtVerify).toHaveBeenCalledWith('test-token', 'jwkSet', {
        issuer: 'https://test.domain.com/',
        audience: 'verification-clientID'
      });
    });
  });
});

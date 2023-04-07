/* eslint-disable no-sync */
import { createCookieSessionStorage, Session } from '@remix-run/node';
import type { SessionStore } from '../Auth0RemixTypes.js';

const bytesToHex = (bytes: Uint8Array) =>
  bytes.reduce((hexstring, byte) => `${hexstring}${byte.toString(16).padStart(2, '0')}`, '');

// const generateCsrfToken = () => Math.random().toString(36).slice(2);

export const generateCsrfToken = () => bytesToHex(crypto.getRandomValues(new Uint8Array(32)));

export const getCsrfCookieStorage = (tokenSecret = process.env.SESSION_SECRET) => {
  console.warn('No secret provided for CSRF cookie storage');
  return createCookieSessionStorage({
    cookie: {
      name: '__csrf-token',
      httpOnly: true,
      path: '/',
      sameSite: false,
      secrets: [tokenSecret].filter(Boolean),
      secure: true
    }
  });
};

const getToken = async (session: Session, tokenStore: SessionStore) => {
  const { store } = tokenStore;
  if ('getToken' in store && typeof store.getToken !== 'undefined') {
    return store.getToken(session);
  }
  return session.get(tokenStore.key);
};

export const getCsrfToken = async (request: Request, tokenStore: SessionStore)=> {
  const { store } = tokenStore;
  const session = await store.getSession(request.headers.get('cookie'));
  return getToken(session, tokenStore);
};

export const verifyCsrfToken = async (request: Request, tokenStore: SessionStore, tokenFromParam: string): Promise<boolean> => {
  const { store } = tokenStore;
  const session = await store.getSession(request.headers.get('cookie'));

  if ('verifyToken' in store && typeof store.verifyToken !== 'undefined') {
    return store.verifyToken(tokenFromParam, session);
  }

  const csrfToken = await getToken(session, tokenStore);

  if (!csrfToken) {
    return false;
  }

  return csrfToken === tokenFromParam;
};

export const generateCsrfCookie = async (request: Request, tokenStore: SessionStore) => {
  const { store: { getSession, commitSession }, key } = tokenStore;
  const session = await getSession(request.headers.get('cookie'));
  if (!session.has(key)) {
    session.set(key, generateCsrfToken());
  }
  const csrfToken = session.get(key);
  return {
    cookie: await commitSession(session),
    token: csrfToken
  };
};

export const destroyCsrfCookie = async (request: Request, tokenStore: SessionStore)=> {
  const { store: { getSession, destroySession } } = tokenStore;
  return destroySession(await getSession(request.headers.get('cookie')));
};

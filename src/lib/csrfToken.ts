/* eslint-disable no-sync */
import { createCookieSessionStorage } from '@remix-run/node';
import bcrypt from 'bcrypt';
import { SessionStore } from '../Auth0RemixTypes.js';

const bytesToHex = (bytes: Uint8Array) =>
  bytes.reduce((hexstring, byte) => `${hexstring}${byte.toString(16).padStart(2, '0')}`, '');

// const generateCsrfToken = () => Math.random().toString(36).slice(2);

export const generateCsrfToken = () => {
  console.log('henlo');
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
};

export const getCsrfCookieStorage = (tokenSecret: string) => createCookieSessionStorage({
  cookie: {
    name: '__csrf-token',
    httpOnly: true,
    path: '/',
    sameSite: false,
    secrets: [tokenSecret],
    secure: true
  }
});

export const verifyCsrfToken = async (request: Request, tokenStore: SessionStore, hash: string): Promise<boolean> => {
  const { store } = tokenStore;
  const session = await store.getSession(request.headers.get('cookie'));
  const csrfToken = session.get(tokenStore.key);
  return csrfToken ? bcrypt.compareSync(csrfToken, atob(hash)) : false;
};

export const generateCsrfCookie = async (request: Request, tokenStore: SessionStore) => {
  const { store: { getSession, commitSession }, key } = tokenStore;
  const session = await getSession(request.headers.get('cookie'));
  const csrfToken = generateCsrfToken();
  session.set(key, csrfToken);
  const hash = bcrypt.hashSync(csrfToken, 10);
  return {
    cookie: await commitSession(session),
    token: btoa(hash)
  };
};

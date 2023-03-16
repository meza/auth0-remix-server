import type { SessionStore, UserCredentials } from '../Auth0RemixTypes.js';

export const saveUserToSession = async (request: Request, userCredentials: UserCredentials, sessionStorage?: SessionStore) => {
  const headers: HeadersInit = {};
  if (sessionStorage) {
    const cookie = request.headers.get('Cookie');
    const session = await sessionStorage.store.getSession(cookie);
    session.set(sessionStorage.key, userCredentials);
    headers['Set-Cookie'] = await sessionStorage.store.commitSession(session);
  } else {
    console.warn('No session storage configured. User credentials will not be persisted.');
  }

  return headers;
};

export const getCredentials = async (request: Request, sessionStore: SessionStore): Promise<UserCredentials> => {
  const cookie = request.headers.get('Cookie');
  const session = await sessionStore.store.getSession(cookie);
  const credentials = session.get(sessionStore.key);
  return credentials;
};

export const saveStateToSession = async (request: Request, state: string, sessionStorage?: SessionStore) => {
  const headers: HeadersInit = {};
  if (sessionStorage) {
    const cookie = request.headers.get('Cookie');
    const session = await sessionStorage.store.getSession(cookie);
    session.set(sessionStorage.key, state);
    headers['Set-Cookie'] = await sessionStorage.store.commitSession(session);
  }

  return headers;
};

<h1><p align="center">Auth0 Remix Server</p></h1>
<p align="center">
The missing library for authentication on the server with Remix
</p>
<p align="center">
<i>Please contribute!</i>
</p>


## What is this?

This is a library for authentication with [Auth0](https://auth0.com/) on the server with Remix.

It's built as part of the efforts to deliver the [trance-stack](https://github.com/meza/trance-stack/). As such, the initial
release of this library only covers the MVP needs of the stack. It will keep evolving over time and with your help.

## Why?

Other solutions out there seem to miss the actual token validation and basic security measures. This library attempts
to bridge that gap and also provide a convenient interface to use.

## What is still missing?

- [ ] utilise the STATE parameter to prevent CSRF
- [ ] failed events should remove the user from the session automatically
- [ ] see if we can handle the callback while maintaining the session from before the login
- [ ] opt out of the session handling

## How to use

Everything below assumes that you're using [Remix](https://remix.run/) and [Auth0](https://auth0.com/) and you're familiar
with how they work.

### Installation

```bash
npm install auth0-remix-server
```

### Usage

Some steps below might be familiar to anyone who attempted this with the [remix-auth-auth0](https://github.com/danestves/remix-auth-auth0/) package.

> #### Environment Variables
> Environment variables are not required for the library, the examples only use them when configuring the authenticator.
> I do recommend using environment variables for sensitive information like client secrets and domain names.
> 
> - `AUTH0_DOMAIN` - The domain name of your Auth0 tenant
> - `AUTH0_CLIENT_ID` - The client ID of your Auth0 application
> - `AUTH0_CLIENT_SECRET` - The client secret of your Auth0 application
> - `APP_DOMAIN` - The domain name of your application (http://localhost:3333 for local development)

#### 1. Create an instance of the authenticator in `src/auth.server.ts`

```ts
// src/auth.server.ts
import { Auth0RemixServer } from 'auth0-remix-server';
import { getSessionStorage } from './sessionStorage.server'; // this is where your session storage is configured

export const authenticator = new Auth0RemixServer({
  clientDetails: {
    domain: process.env.AUTH0_DOMAIN,
    clientID: process.env.AUTH0_CLIENT_ID,
    clientSecret: process.env.AUTH0_CLIENT_SECRET
  },
  callbackURL: `${process.env.APP_DOMAIN}/auth/callback`,
  refreshTokenRotationEnabled: true,
  failedLoginRedirect: '/',
  session: {
    store: getSessionStorage(),
    key: 'user' //optional
  },
  credentialsCallback: (credentials) => {
      // this gets called upon a successful callback or a credentials refresh event
  } //optional
});
```

#### 2. Create a login route in `src/routes/login.tsx`

```tsx
// src/routes/login.tsx
import { Form } from '@remix-run/react';
import { redirect } from '@remix-run/node';

export default () => {
  return (
    <Form action="/auth/auth0" method="post">
      <button>Login</button>
    </Form>
  );
};
```

#### 3. Create an authentication route in `src/routes/auth/auth0.ts`

```tsx
// src/routes/auth/auth0.ts
import { authenticator } from '../../auth.server';
import type { ActionFunction } from '@remix-run/node';

export const action: ActionFunction = () => {
  authenticator.authorize();
};
```

> *Note* You can modify the behaviour of the `authorize` method. More on that [here](#modifying-the-authorize-process)

#### 4. Create a callback route in `src/routes/auth/callback.tsx`

```tsx
// src/routes/auth/callback.tsx
import { authenticator } from '../../auth.server';
import type { ActionFunction } from '@remix-run/node';

export const action: ActionFunction = async ({ request }) => {
  await authenticator.handleCallback(request, {
    onSuccessRedirect: '/dashboard' // change this to be wherever you want to redirect to after a successful login
  });
};
```

#### 5. Create a logout route in `src/routes/logout.tsx`

```tsx
import { authenticator } from '../auth.server';
import { destroySession, getSessionFromRequest } from '../session.server';
import type { ActionFunction } from '@remix-run/node';

export const action: ActionFunction = async ({ request }) => {
  const session = await getSessionFromRequest(request);

  await authenticator.logout(process.env.APP_DOMAIN, {
    'Set-Cookie': await destroySession(session) // this is where you destroy the session
  });
};

export const loader = action; // this to allow you to hit /logout directly in the browser
```

#### 6. Optional - Create a dashboard route in `src/routes/dashboard.tsx`

```tsx
import { json } from '@remix-run/node';
import { Form, useLoaderData } from '@remix-run/react';
import { authenticator } from '../auth.server';
import type { LoaderFunction } from '@remix-run/node';

export const loader: LoaderFunction = async ({ request, context }) => {
  const user = await authenticator.getUser(request, context); // this is what determines if the user is logged in or not
  return json({
    user: user
  });
};

export default () => {
  const { user } = useLoaderData<typeof loader>();
  return (
    <div>
      <div>Dashboard for {user.nickname || user.givenName || user.name}</div>
      <Form action="/logout" method="post">
        <button>Logout</button>
      </Form>
    </div>
  );
};


```

## Securely decoding tokens

If you're using the contents of the tokens, you should always make sure that they're valid and haven't been tampered with.
You can quickly verify the validity of the tokens by using the `verifyToken` and `isValid` methods on the authenticator
described in the [Validating Tokens](#validating-tokens) section.

But if you want to decode the tokens and use the contents, you should use the `decodeToken` method .

```ts
import { authenticator } from './auth.server';
import { Token } from 'auth0-remix-server';

const decodedToken = await authenticator.decodeToken('your id token here', Token.ID);
```

The `decodedToken` will contain the contents of the IDToken but at this point you can be sure that it passed
the cryptographic validation checks.

If the verification fails, the `decodeToken` method will throw the same set of errors as the `verifyToken` method throws.
You can see the list of errors in the [Errors](#errors) section.

## Validating Tokens

ID and Access Tokens can be decoded easily by anyone but in order to make sure that the data hasn't been
tampered with, it's advisable to validate the tokens against the public keys provided by Auth0.

You can do this by using the `verifyToken` and the `isValid` methods on the authenticator.
They both take a `Token` as a second argument because the validation process is different for each type of token.

The `isValid` function is a quick yes/no answer to whether or not the token is valid.

```ts
import { authenticator } from './auth.server';
import { Token } from 'auth0-remix-server';

await authenticator.isValid('your access token here', Token.AccessToken); // returns true or false
```

The `verifyToken` function will resolve if the token is valid and will reject if it's not.

```ts
import { authenticator } from './auth.server';
import { Token } from 'auth0-remix-server';

try {
  await authenticator.verifyToken('your id token here', Token.ID);
} catch (error) {
  // handle the error
  const { code, message } = error as TokenError;
}
```

## Modifying the Authorize process

### Forcing a login

During the authrization process, if the user is already logged into Auth0, they will not be asked to log in again.
You can change that behaviour by passing in the `forceLogin` option to the `authorize` method.

```tsx
// src/routes/auth/auth0.ts
import { authenticator } from '../../auth.server';
import type { ActionFunction } from '@remix-run/node';

export const action: ActionFunction = () => {
  authenticator.authorize({
    forceLogin: true
  });
};
```

### Forcing a signup

You can force the user to the sign-up page by passing in the `forceSignup` option to the `authorize` method.

```tsx
// src/routes/auth/auth0.ts
import { authenticator } from '../../auth.server';
import type { ActionFunction } from '@remix-run/node';

export const action: ActionFunction = () => {
  authenticator.authorize({
    forceSignup: true
  });
};
```

### Forcing a silent authentication

You can force the user to the sign-up page by passing in the `forceSignup` option to the `authorize` method.

```tsx
// src/routes/auth/auth0.ts
import { authenticator } from '../../auth.server';
import type { ActionFunction } from '@remix-run/node';

export const action: ActionFunction = () => {
  authenticator.authorize({
    silentAuth: true
  });
};
```

Combining the `forceLogin`, `forceSignup` and `silentAuth` parameters to control the behavior of the authorization request produce the following results:

| parameter                               | No existing session   | Existing session              |
|-----------------------------------------|-----------------------|-------------------------------|
| `{forceSignup: true}`                   | Shows the signup page | Redirects to the callback url |
| `{forceLogin: true}`                    | Shows the login page  | Shows the login page          |
| `{forceSignup: true, forceLogin: true}` | Shows the signup page | Shows the signup page         |
| `{silentAuth: true, forceLogin: true}`  | Silent auth           | Silent auth                   |
| `{silentAuth: true, forceSignup: true}` | Needs testing         | Needs testing                 |


### Adding a connection

You can also specify the name of the connection configured to your application.

```tsx
// src/routes/auth/auth0.ts
import { authenticator } from '../../auth.server';
import type { ActionFunction } from '@remix-run/node';

export const action: ActionFunction = () => {
  authenticator.authorize({
    connection: 'google'
  });
};
```

## Errors

The verification errors each have a `code` property that you can use to determine what went wrong.

| Code                            | Description                        |
|---------------------------------|------------------------------------|
| ERR_JWT_CLAIM_VALIDATION_FAILED | The JWT claim validation failed.   |
| ERR_JWT_EXPIRED                 | The JWT has expired.               |
| ERR_JWT_INVALID                 | The JWT is invalid.                |
| ERR_JWKS_INVALID                | The JWKS is invalid.               |
| ERR_JWKS_NO_MATCHING_KEY        | No matching key was found.         |
| ERR_JWKS_MULTIPLE_MATCHING_KEYS | Multiple matching keys were found. |


## Gotchas

### Accessing the tokens

When you instantiate the authenticator, you can pass in a `credentialsCallback` function. This function will be called
when the user is successfully authenticated or when the access token is refreshed.

It will contain the credentials obtained from Auth0.

The credentials object looks like this:

```
{
  accessToken: string; // the access token
  refreshToken: string; // the refresh token
  expiresIn: number; // the number of seconds until the access token expires
  expiresAt: number; // the timestamp when the access token expires
  lastRefreshed: number; // the timestamp when the access token was last refreshed
}
```

### Refresh Token Rotation

The `refreshTokenRotationEnabled` option is set to `false` by default. This is because it's off by default in Auth0.

When it's set to `true`, the refresh tokens will be appended to the session. This is secure and makes it easier to manage
the refresh tokens.

Please see [this post](https://auth0.com/docs/tokens/refresh-tokens/refresh-token-rotation) and [this one](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/#Refresh-Token-Rotation)
for more information.

### Refreshing the access token

Until [this issue](https://github.com/remix-run/react-router/issues/9566) in Remix is shipped, you'll need to pass in
the context from the loaders and actions to the `getUser` method.

This ensures (in an awkward way) that the refresh only happens once.

It's not pretty but once we have proper middleware in Remix, it should clean up.



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

## What is still missing?

- [ ] utilise the STATE parameter to prevent CSRF
- [ ] failed events should remove the user from the session automatically
- [ ] see if we can handle the callback while maintaining the session from before the login
- [ ] create the callbacks for the id token and the refresh tokens
- [ ] opt out of the session handling
- [ ] enable register with passing ?screen_hint=signup to the authorize endpoint

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
import { Index } from 'auth0-remix-server';
import { getSessionStorage } from './sessionStorage.server'; // this is where your session storage is configured

export const authenticator = new Index({
  clientDetails: {
    domain: process.env.AUTH0_DOMAIN,
    clientID: process.env.AUTH0_CLIENT_ID,
    clientSecret: process.env.AUTH0_CLIENT_SECRET
  },
  callbackURL: `${process.env.APP_DOMAIN}/auth/callback`,
  refreshTokenRotationEnabled: true,
  failedLoginRedirect: '/',
  session: {
    store: getSessionStorage()
  }
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
  const forceLogin = false; // set to true to force auth0 to ask for a login
  authenticator.authorize(forceLogin);
};
```

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

## Gotchas

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



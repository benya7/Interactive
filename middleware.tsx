import { NextResponse, NextRequest } from 'next/server';

const authWeb = `${process.env.NEXT_PUBLIC_APP_URI}/user`;

export type MiddlewareHook = (req: NextRequest) => Promise<{
  activated: boolean;
  response: NextResponse;
}>;

export const generateCookieString = (key: string, value: string, age: string): string =>
  `${key}=${value}; Domain=${process.env.NEXT_PUBLIC_COOKIE_DOMAIN}; Path=/; Max-Age=${age}; SameSite=strict;`;

export const getQueryParams = (req: NextRequest): Record<string, string> =>
  req.url.includes('?')
    ? Object.assign(
        {},
        ...req.url
          .split('?')[1]
          .split('&')
          .map((param) => ({ [param.split('=')[0]]: param.split('=')[1] })),
      )
    : {};

export const getRequestedURI = (req: NextRequest): string => {
  return req.url
    .split('?')[0]
    .replace(/localhost:\d+/, (process.env.APP_URI || '').replace('https://', '').replace('http://', ''));
};

export const getJWT = (req: NextRequest) => {
  const rawJWT = req.cookies.get('jwt')?.value;
  const jwt = rawJWT?.split(' ')[rawJWT?.split(' ').length - 1] ?? rawJWT ?? '';
  return jwt;
};

export const verifyJWT = async (jwt: string): Promise<Response> => {
  console.log('Verifying JWT:', jwt.slice(0, 10) + '...');
  if (!process.env.SERVERSIDE_AGIXT_SERVER) {
    process.env.SERVERSIDE_AGIXT_SERVER = ['agixt', 'localhost', 'back-end', 'boilerplate', 'back-end-image'].join(',');
  }
  const containerNames = process.env.SERVERSIDE_AGIXT_SERVER.split(',');
  const responses = {} as any;
  const authEndpoint = `${process.env.AGIXT_SERVER}/v1/user`;
  let response;
  for (const containerName of containerNames) {
    const testEndpoint = authEndpoint.replace('localhost', containerName);
    try {
      response = await fetch(testEndpoint, {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `${jwt}`,
        },
      });
      console.log(`JWT verification response from ${testEndpoint}: ${response.status}`);
      if (response.status === 200 || [401, 402, 403].includes(response.status)) {
        if (Object.keys(responses).length > 0) {
          containerNames.sort((a, b) => (a === containerName ? -1 : b === containerName ? 1 : 0));
          process.env.SERVERSIDE_AGIXT_SERVER = containerNames.join(',');
        }
        return response;
      } else {
        responses[testEndpoint] = await response.text();
        console.error(`Failed to contact server at ${testEndpoint}.`);
      }
    } catch (exception) {
      responses[testEndpoint] = exception;
      console.error(`Error contacting ${testEndpoint}:`, exception);
    }
  }
  console.error('Failed to contact any servers:', JSON.stringify(responses));
  return new Response('No servers available', { status: 503 });
};

export const useAuth: MiddlewareHook = async (req) => {
  console.log('Entering useAuth hook for:', req.nextUrl.pathname);
  const toReturn = {
    activated: false,
    response: NextResponse.redirect(new URL(authWeb as string), {
      headers: {
        'Set-Cookie': [generateCookieString('jwt', '', '0')],
      },
    }),
  };

  const requestedURI = getRequestedURI(req);
  const queryParams = getQueryParams(req);

  if (requestedURI.endsWith('/user/logout')) {
    console.log('Skipping auth for logout path');
    return toReturn;
  }

  if (queryParams['verify_email'] && queryParams['email']) {
    console.log('Handling email verification');
    try {
      const response = await fetch(`${process.env.AGIXT_SERVER}/v1/user/verify/email`, {
        method: 'POST',
        body: JSON.stringify({
          email: queryParams['email'],
          code: queryParams['verify_email'],
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      });
      console.log('Email verification response:', response.status);
    } catch (error) {
      console.error('Email verification failed:', error);
    }

    if (queryParams.invitation_id && queryParams.email) {
      const cookieArray = [
        generateCookieString('email', queryParams.email, '86400'),
        generateCookieString('invitation', queryParams.invitation_id, '86400'),
      ];
      if (queryParams.company) {
        cookieArray.push(generateCookieString('company', queryParams.company, '86400'));
      }
      toReturn.activated = true;
      toReturn.response = NextResponse.redirect(`${authWeb}/register`, {
        headers: {
          'Set-Cookie': cookieArray,
        },
      });
      console.log('Redirecting to register with cookies');
      return toReturn;
    }
  }

  const isPrivateRoute = process.env.PRIVATE_ROUTES?.split(',').some((path) => req.nextUrl.pathname.startsWith(path));
  console.log('Is private route:', isPrivateRoute);

  if (
    req.nextUrl.pathname.startsWith('/user/close') ||
    req.nextUrl.pathname === '/user' ||
    req.nextUrl.pathname === '/user/login' ||
    req.nextUrl.pathname === '/user/register'
  ) {
    console.log('Skipping auth for public user route');
    toReturn.activated = false;
    return toReturn;
  }

  if (!isPrivateRoute && !req.nextUrl.pathname.startsWith('/user')) {
    console.log('Skipping auth for non-private, non-user route');
    toReturn.activated = false;
    return toReturn;
  }

  const jwt = getJWT(req);
  console.log('JWT found:', !!jwt);

  if (
    !jwt &&
    (isPrivateRoute ||
      (req.nextUrl.pathname.startsWith('/user') &&
        !req.nextUrl.pathname.startsWith('/user/register') &&
        !req.nextUrl.pathname.startsWith('/user/login') &&
        req.nextUrl.pathname !== '/user'))
  ) {
    console.log('No JWT for private route, redirecting');
    toReturn.activated = true;
    toReturn.response.headers.set('Set-Cookie', [
      generateCookieString('jwt', '', '0'),
      generateCookieString('href', requestedURI, '86400'),
    ]);
    return toReturn;
  }

  if (jwt) {
    try {
      const response = await verifyJWT(jwt);
      const responseJSON = await response.json();
      console.log('JWT verification status:', response.status);

      if (response.status === 402) {
        if (!requestedURI.startsWith(`${authWeb}/subscribe`)) {
          toReturn.response = NextResponse.redirect(
            new URL(
              `${authWeb}/subscribe${
                responseJSON.detail.customer_session.client_secret
                  ? '?customer_session=' + responseJSON.detail.customer_session.client_secret
                  : ''
              }`,
            ),
          );
          toReturn.activated = true;
          console.log('Redirecting to subscribe due to payment required');
        }
      } else if (responseJSON?.missing_requirements || response.status === 403) {
        if (!requestedURI.startsWith(`${authWeb}/manage`)) {
          toReturn.response = NextResponse.redirect(new URL(`${authWeb}/manage`));
          toReturn.activated = true;
          console.log('Redirecting to manage due to missing requirements');
        }
      } else if (response.status === 502) {
        const cookieArray = [generateCookieString('href', requestedURI, '86400')];
        toReturn.activated = true;
        toReturn.response = NextResponse.redirect(new URL(`${authWeb}/down`, req.url), {
          headers: {
            'Set-Cookie': cookieArray,
          },
        });
        console.log('Redirecting to down page due to 502');
      } else if (response.status >= 500 && response.status < 600) {
        console.error(`Server error ${response.status}: ${responseJSON.detail}`);
        toReturn.response = NextResponse.redirect(new URL(`${authWeb}/error`, req.url));
        toReturn.activated = true;
      } else if (response.status !== 200) {
        toReturn.response = NextResponse.redirect(new URL(authWeb, req.url), {
          headers: {
            'Set-Cookie': [
              generateCookieString('jwt', '', '0'),
              generateCookieString('href', requestedURI, '86400'),
            ],
          },
        });
        toReturn.activated = true;
        console.error(`Invalid JWT response ${response.status}: ${responseJSON.detail}`);
      } else if (requestedURI.startsWith(authWeb) && jwt.length > 0 && !['/user/manage'].includes(req.nextUrl.pathname)) {
        toReturn.response = NextResponse.redirect(new URL(`${authWeb}/manage`));
        toReturn.activated = true;
        console.log('Redirecting to manage with valid JWT');
      }
    } catch (exception) {
      logJwtError(exception, authWeb);
      toReturn.response = NextResponse.redirect(new URL(authWeb, req.url), {
        headers: {
          'Set-Cookie': [
            generateCookieString('jwt', '', '0'),
            generateCookieString('href', requestedURI, '86400'),
          ],
        },
      });
      toReturn.activated = true;
    }
  }

  return toReturn;
};

function logJwtError(exception: any, authWeb: string) {
  if (exception instanceof TypeError && exception.cause instanceof AggregateError) {
    console.error(
      `Invalid token. TypeError>AggregateError. Redirecting to ${authWeb}. ${exception.message}`,
    );
    for (const anError of exception.cause.errors) {
      console.error(anError.message);
    }
  } else if (exception instanceof AggregateError) {
    console.error(`Invalid token. AggregateError. Redirecting to ${authWeb}. ${exception.message}`);
    for (const anError of exception.errors) {
      console.error(anError.message);
    }
  } else if (exception instanceof TypeError) {
    console.error(`Invalid token. TypeError. Redirecting to ${authWeb}. ${exception.message}`);
  } else {
    console.error(`Invalid token. Redirecting to ${authWeb}.`, exception);
  }
}

export const useOAuth2: MiddlewareHook = async (req) => {
  console.log('Entering useOAuth2 hook for:', req.nextUrl.pathname);
  const provider = req.nextUrl.pathname.split('?')[0].split('/').pop();
  const redirect = new URL(`${authWeb}/close/${provider}`);
  let toReturn = {
    activated: false,
    response: NextResponse.redirect(redirect),
  };
  const queryParams = getQueryParams(req);
  if (queryParams.code) {
    const oAuthEndpoint = `${process.env.AGIXT_SERVER || ''.replace('localhost', (process.env.SERVERSIDE_AGIXT_SERVER || '').split(',')[0])}/v1/oauth2/${provider}`;
    const jwt = getJWT(req);

    try {
      console.log('Attempting OAuth2 request to:', oAuthEndpoint);
      const response = await fetch(oAuthEndpoint, {
        method: 'POST',
        body: JSON.stringify({
          code: queryParams.code,
          referrer: redirect.toString(),
          state: queryParams.state,
          invitation: req.cookies.get('invitation')?.value,
        }),
        headers: {
          'Content-Type': 'application/json',
          Authorization: jwt || '',
        },
      });

      const auth = await response.json();
      console.log('OAuth2 response status:', response.status);

      if (response.status !== 200) {
        throw new Error(`Invalid token response, status ${response.status}.`);
      }

      const headers = new Headers();
      if (jwt) {
        headers.set('Authorization', jwt);
      }

      toReturn = {
        activated: true,
        response: NextResponse.redirect(auth.detail, {
          headers: headers,
        }),
      };
      console.log('OAuth2 successful, redirecting to:', auth.detail);
    } catch (error) {
      console.error('OAuth2 error:', error);
    }
  }
  return toReturn;
};

export const useJWTQueryParam: MiddlewareHook = async (req) => {
  console.log('Entering useJWTQueryParam hook for:', req.nextUrl.pathname);
  const queryParams = getQueryParams(req);
  const requestedURI = getRequestedURI(req);
  const toReturn = {
    activated: false,
    response: req.nextUrl.pathname.startsWith('/user/close')
      ? NextResponse.next({
          headers: {
            'Set-Cookie': [generateCookieString('jwt', queryParams.token ?? queryParams.jwt, '604800')],
          },
        })
      : NextResponse.redirect(req.cookies.get('href')?.value ?? process.env.APP_URI ?? '', {
          headers: {
            'Set-Cookie': [
              generateCookieString('jwt', queryParams.token ?? queryParams.jwt, '604800'),
              generateCookieString('href', '', '0'),
            ],
          },
        }),
  };
  if (queryParams.token || queryParams.jwt) {
    toReturn.activated = true;
    console.log('JWT query param found, setting cookie');
  }
  return toReturn;
};

export const useNextAPIBypass: MiddlewareHook = async (req) => {
  console.log('Entering useNextAPIBypass hook for:', req.nextUrl.pathname);
  const toReturn = {
    activated: false,
    response: NextResponse.next(),
  };
  if (
    req.nextUrl.pathname.startsWith('/_next/') ||
    req.nextUrl.pathname.startsWith('/api/') ||
    req.nextUrl.pathname === '/favicon.ico'
  ) {
    toReturn.activated = true;
    console.log('Bypassing for Next.js assets or API');
  }
  return toReturn;
};

export const useSocketIOBypass: MiddlewareHook = async (req) => {
  console.log('Entering useSocketIOBypass hook for:', req.nextUrl.pathname);
  const url = new URL(getRequestedURI(req));
  const activated = url.host === 'socket.io';
  console.log('Socket.IO bypass activated:', activated);
  return {
    activated,
    response: NextResponse.next(),
  };
};

export const useDocsPublicAccess: MiddlewareHook = async (req) => {
  console.log('Entering useDocsPublicAccess hook for:', req.nextUrl.pathname);
  if (req.nextUrl.pathname === '/docs') {
    console.log('Redirecting /docs to /docs/0-Introduction');
    return {
      activated: true,
      response: NextResponse.redirect(new URL('/docs/0-Introduction', req.url)),
    };
  }
  const activated = req.nextUrl.pathname.startsWith('/docs');
  console.log('Docs public access activated:', activated);
  return {
    activated,
    response: NextResponse.next(),
  };
};

export default async function Middleware(req: NextRequest): Promise<NextResponse> {
  console.log('Middleware processing request:', req.nextUrl.pathname);
  const hooks = [useNextAPIBypass, useDocsPublicAccess, useOAuth2, useJWTQueryParam, useAuth];
  for (const hook of hooks) {
    const hookResult = await hook(req);
    if (hookResult.activated) {
      hookResult.response.headers.set('x-next-pathname', req.nextUrl.pathname);
      console.log('Hook activated:', hook.name);
      return hookResult.response;
    }
  }
  console.log('No hooks activated, proceeding with next');
  return NextResponse.next({
    headers: {
      'x-next-pathname': req.nextUrl.pathname,
    },
  });
}
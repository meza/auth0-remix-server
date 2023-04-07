import { iterableToObject } from '@test/iterators.js';
import { describe, it, expect } from 'vitest';
import { mergeHeaders } from './mergeHeaders.js';

const SET_COOKIE_SESSION = '__session=test; Max-Age=31536000; Path=/; HttpOnly; Secure; SameSite=Lax';
const SET_COOKIE_CSRF_TOKEN = '__csrf-token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly';

describe('mergeHeaders', () => {
  it.each<[string, HeadersInit[]]>([
    [
      'Headers objects', [
        new Headers({ 'set-cookie': SET_COOKIE_SESSION }),
        new Headers({ 'set-cookie': SET_COOKIE_CSRF_TOKEN, 'content-type': 'application/json' })
      ]
    ],
    [
      'plain objects', [
        { 'set-cookie': SET_COOKIE_SESSION },
        { 'set-cookie': SET_COOKIE_CSRF_TOKEN, 'content-type': 'application/json' }
      ]
    ],
    [
      'string arrays', [
        [['set-cookie', SET_COOKIE_SESSION]],
        [['set-cookie', SET_COOKIE_CSRF_TOKEN], ['content-type', 'application/json']]
      ]
    ]
  ])('should merge headers (%s)', (_, headerInits) => {
    const actual = mergeHeaders(...headerInits);

    expect(iterableToObject(actual)).toEqual({
      'set-cookie': [
        SET_COOKIE_SESSION,
        SET_COOKIE_CSRF_TOKEN
      ].join(', '),
      'content-type': 'application/json'
    });
  });
});

/* eslint-disable camelcase */
import { describe, expect, it } from 'vitest';
import { transformUserData } from './transformUserData.js';
import type { Auth0UserProfile, UserProfile } from '../Auth0RemixTypes.js';

describe('transformUserData', () => {
  it('should work', () => {
    const input: Auth0UserProfile = {
      name: 'John Doe',
      email: 'jd@example.com',
      given_name: 'John',
      family_name: 'Doe',
      sub: 'Something',
      picture: 'some-url',
      nickname: 'J',
      updatedAt: '2023-02-27T23:10:18.458Z',
      an_object: {
        with_a_nested_object: {
          and_a_nested_array: ['with', 'some', 'values']
        }
      }
    };

    const expected: UserProfile = {
      name: 'John Doe',
      email: 'jd@example.com',
      givenName: 'John',
      familyName: 'Doe',
      sub: 'Something',
      picture: 'some-url',
      nickname: 'J',
      updatedAt: '2023-02-27T23:10:18.458Z',
      anObject: {
        withANestedObject: {
          andANestedArray: ['with', 'some', 'values']
        }
      }
    };

    const actual = transformUserData(input);

    expect(actual).toEqual(expected);
  });
});

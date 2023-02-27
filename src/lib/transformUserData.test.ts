import { describe, expect, it } from 'vitest';
import { transformUserData } from './transformUserData.js';
import type { Auth0UserProfile } from '../Auth0RemixTypes.js';

describe('transformUserData', () => {
  it('should work', () => {
    const input = {
      name: 'John Doe',
      email: 'jd@example.com',
      // eslint-disable-next-line camelcase
      first_name: 'John',
      // eslint-disable-next-line camelcase
      last_name: 'Doe',
      // eslint-disable-next-line camelcase
      an_object: {
        // eslint-disable-next-line camelcase
        with_a_nested_object: {
          // eslint-disable-next-line camelcase
          and_a_nested_array: ['with', 'some', 'values']
        }
      }
    } as Auth0UserProfile;

    const expected = {
      name: 'John Doe',
      email: 'jd@example.com',
      firstName: 'John',
      lastName: 'Doe',
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

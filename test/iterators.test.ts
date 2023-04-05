import { describe, it, expect } from 'vitest';
import { iterableToObject } from './iterators.js';

describe('Iterator helpers', () => {
  describe('Headers to object', () => {
    const headers = new Headers({
      'content-type': 'text/html',
      cookie: 'cookie-string'
    });

    it('should return correct object', () => {
      expect(iterableToObject(headers)).toEqual({
        'content-type': 'text/html',
        cookie: 'cookie-string'
      });
    });
  });

  describe('Search params to object', () => {
    const search = new URLSearchParams();
    search.append('foo', 'bar');
    search.append('foo', 'baz');
    search.append('foo', 'qux');
    search.append('hello', 'world');

    it('should return correct object', () => {
      expect(iterableToObject(search)).toMatchObject({
        foo: ['bar', 'baz', 'qux'],
        hello: 'world'
      });
    });
  });
});

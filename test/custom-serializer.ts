import { iterableToObject } from '@test/iterators.js';
import { expect } from 'vitest';

expect.addSnapshotSerializer({
  serialize: (val: Headers | URLSearchParams, config, indentation, depth, refs, printer) =>
    printer(iterableToObject(val), config, indentation, depth, refs),
  test: (val) => val && (val instanceof Headers || val instanceof URLSearchParams)
});

import { afterEach, vi } from 'vitest';
import './test/custom-serializer.js';

(await import('@remix-run/node')).installGlobals();

afterEach(() => {
  // these run after every single test
  // vi.unstubAllEnvs();
  // vi.unstubAllGlobals();
  // vi.resetAllMocks();
  // vi.useRealTimers();
});

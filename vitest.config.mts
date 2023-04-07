import isCi from 'is-ci';
import tsconfigPaths from 'vite-tsconfig-paths';
import { defineConfig } from 'vitest/config';
import type { CoverageReporter } from 'vitest';

const testReporters = ['default'];
const coverageReporters: CoverageReporter[] = ['text'];

if (!isCi) {
  // testReporters.push('cobertura');
  coverageReporters.push('html');
} else {
  testReporters.push('junit');
  coverageReporters.push('cobertura');
}

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    globals: true,
    isolate: true,
    cache: {
      dir: '.cache/.vitest'
    },
    deps: {
      fallbackCJS: true
    },
    setupFiles: ['vitest.setup.mts'],
    dir: 'src',
    testTimeout: 10000,
    watch: false,
    maxThreads: 1,
    minThreads: 1,
    outputFile: 'reports/junit.xml',
    reporters: testReporters,
    coverage: {
      src: ['src'],
      include: ['**/*.ts', '**/*.tsx'],
      exclude: [
        '**/__mocks__/**.*',
        '**/*.d.ts',
        '**/*.test.ts',
        '**/*.test.tsx',
        'test/**.*',
        'src/Auth0RemixTypes.ts'
      ],
      all: true,
      reportsDirectory: './reports/coverage/unit',
      reporter: coverageReporters,
      statements: 100,
      branches: 100,
      functions: 100,
      lines: 100
    }
  },
});

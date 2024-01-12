import path from 'node:path';
import isCi from 'is-ci';
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
  test: {
    globals: true,
    isolate: true,
    cache: {
      dir: '.cache/.vitest'
    },
    dir: 'src',
    testTimeout: 10000,
    watch: false,
    outputFile: 'reports/junit.xml',
    reporters: testReporters,
    coverage: {
      include: ['src/**/*.ts', 'src/**/*.tsx'],
      exclude: [
        '**/__mocks__/**.*',
        '**/*.d.ts',
        '**/*.test.ts',
        '**/*.test.tsx',
        '**/*.stories.mdx',
        '**/*.stories.tsx',
        'test/**.*',
        'src/Auth0RemixTypes.ts'
      ],
      all: true,
      reportsDirectory: './reports/coverage/unit',
      reporter: coverageReporters,
      thresholds: {
        statements: 100,
        branches: 100,
        functions: 100,
        lines: 100
      }
    }
  },
  resolve: {
    alias: {
      '~': path.resolve(__dirname, './src')
    }
  }
});

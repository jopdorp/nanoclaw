import { expect, it, vi } from 'vitest';

import { createUpdateChecker } from './updates.js';

it('lists Helm releases only through namespace-scoped access', async () => {
  const helm = vi.fn(async (args: string[]) =>
    args[2] === 'forbidden'
      ? Promise.reject(new Error('secrets is forbidden'))
      : JSON.stringify([{ name: args[2], namespace: args[2], chart: 'test-1.0.0' }]),
  );
  const check = createUpdateChecker({
    reader: {
      request: async (url: string) =>
        url == '/api/v1/namespaces'
          ? {
              items: ['default', 'forbidden', 'nanoclaw-remediator', 'orfie-ci'].map((name) => ({
                metadata: { name },
              })),
            }
          : { items: [] },
      watch: async function* () {},
    },
    helm,
    charts: {},
    fetch: vi.fn(),
  });

  const result = JSON.parse(await check());
  expect(result.helm.rows).toHaveLength(1);
  expect(result.helm.notes).toEqual(['skipped forbidden: Helm release listing forbidden']);
  expect(helm).toHaveBeenCalledWith(['list', '-n', 'default', '-o', 'json']);
});

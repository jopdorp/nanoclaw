import { expect, it, vi } from 'vitest';

import { createUpdateChecker } from './updates.js';

it('lists Helm releases only through namespace-scoped access', async () => {
  const helm = vi.fn(async (args: string[]) =>
    JSON.stringify([{ name: args[2], namespace: args[2], chart: 'test-1.0.0' }]),
  );
  const check = createUpdateChecker({
    reader: {
      request: async (url: string) =>
        url == '/api/v1/namespaces'
          ? {
              items: ['default', 'nanoclaw-remediator', 'orfie-ci'].map((name) => ({ metadata: { name } })),
            }
          : { items: [] },
      watch: async function* () {},
    },
    helm,
    charts: {},
    fetch: vi.fn(),
  });

  expect(JSON.parse(await check()).helm.rows).toHaveLength(1);
  expect(helm).toHaveBeenCalledWith(['list', '-n', 'default', '-o', 'json']);
});

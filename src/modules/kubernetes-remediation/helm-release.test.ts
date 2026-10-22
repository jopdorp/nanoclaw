import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { expect, it, vi } from 'vitest';

import { gitWithDeployKey, HelmReleaseExecutor } from './helm-release.js';
import { validateRemediationPlan } from './policy.js';
import type { HelmValuesPlan } from './types.js';

it('a values file that drifted from before gets no helm upgrade and no commit', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'helm-release-'));
  const remote = path.join(dir, 'remote.git');
  const seed = path.join(dir, 'seed');
  const git = (cwd: string, ...args: string[]) =>
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...args], { cwd, encoding: 'utf8' });
  git(dir, 'init', '-q', '--bare', '-b', 'master', remote);
  git(dir, 'init', '-q', '-b', 'master', seed);
  fs.mkdirSync(path.join(seed, 'kubernetes/helm-charts'), { recursive: true });
  fs.writeFileSync(path.join(seed, 'kubernetes/helm-charts/gitea-values.yaml'), 'image:\n  tag: "1.27.0"\n');
  git(seed, 'add', '.');
  git(seed, 'commit', '-q', '-m', 'seed');
  git(seed, 'push', '-q', remote, 'HEAD:master');

  const helm = vi.fn(async (_args: string[]) => JSON.stringify({ chart: 'gitea', version: '12.6.0', revision: 10 }));
  const checkout = path.join(dir, 'checkout');
  const executor = new HelmReleaseExecutor({
    client: {
      request: async () => ({
        items: [{ metadata: { uid: 'uid-1', resourceVersion: '42', labels: { version: '10' } } }],
      }),
      watch: async function* () {},
    },
    charts: {
      'gitea/gitea': {
        chart: 'gitea',
        repo: 'https://dl.gitea.com/charts/',
        file: 'kubernetes/helm-charts/gitea-values.yaml',
      },
    },
    checkout,
    memoryDir: path.join(dir, 'memory'),
    helm,
    git: gitWithDeployKey(checkout, dir),
    remote,
  });
  const { plan } = validateRemediationPlan({
    schemaVersion: 1,
    id: randomUUID(),
    incidentIds: ['trivy:one:2'],
    target: {
      apiVersion: 'v1',
      kind: 'Secret',
      namespace: 'gitea',
      name: 'gitea',
      uid: 'uid-1',
      resourceVersion: '42',
    },
    reason: 'pin the gitea digest',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    operation: {
      type: 'helm-values',
      file: 'kubernetes/helm-charts/gitea-values.yaml',
      set: [{ path: 'image.tag', before: '1.26.0', after: `1.26.0@sha256:${'a'.repeat(64)}` }],
    },
  });

  await expect(executor.apply(plan as HelmValuesPlan)).rejects.toThrow('repo drift: image.tag is "1.27.0"');
  expect(helm.mock.calls.map(([args]) => args[0])).toEqual(['get']);
  expect(git(remote, 'rev-list', '--count', 'master').trim()).toBe('1');
});

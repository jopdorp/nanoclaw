import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { expect, it, vi } from 'vitest';

import { editValues, gitWithDeployKey, HelmReleaseExecutor } from './helm-release.js';
import { validateRemediationPlan } from './policy.js';
import type { HelmValuesPlan } from './types.js';

function fixture(before: string, workload: unknown = {}, live = 'image:\n  tag: "1.27.0"\n') {
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

  const helm = vi.fn(async (args: string[]) =>
    args[0] === 'show'
      ? 'name: gitea\nversion: 12.6.0\n'
      : args[1] === 'values'
        ? live
        : args[1] === 'manifest'
          ? ''
          : JSON.stringify({ chart: 'gitea', version: '12.6.0', revision: 10 }),
  );
  const checkout = path.join(dir, 'checkout');
  const executor = new HelmReleaseExecutor({
    client: {
      request: async (url: string, init?: { body?: unknown }) =>
        url.includes('/secrets?')
          ? { items: [{ metadata: { uid: 'uid-1', resourceVersion: '42', labels: { version: '10' } } }] }
          : typeof workload === 'function'
            ? workload(url, init)
            : workload,
      watch: async function* () {},
    },
    charts: {
      'gitea/gitea': {
        chart: 'gitea',
        repo: 'https://dl.gitea.com/charts/',
        file: 'kubernetes/helm-charts/gitea-values.yaml',
      },
    },
    remember: () => undefined,
    checkout,
    memoryDir: path.join(dir, 'memory'),
    helm,
    git: gitWithDeployKey(checkout, dir),
    remote,
    notify: async () => undefined,
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
      set: [{ path: 'image.tag', before, after: `${before}@sha256:${'a'.repeat(64)}` }],
    },
  });
  const commits = () => git(remote, 'rev-list', '--count', 'master').trim();
  return { dir, executor, helm, plan: plan as HelmValuesPlan, commits };
}

it('a values file that drifted from before gets no helm upgrade and no commit', async () => {
  const { executor, helm, plan, commits } = fixture('1.26.0');
  await expect(executor.apply(plan)).rejects.toThrow('repo drift: image.tag is "1.27.0"');
  expect(helm.mock.calls.map(([args]) => args[0])).toEqual(['status', 'get', 'show', 'get']);
  expect(commits()).toBe('1');
});

it('a values file that differs from the live release values needs helm-sync-values first', async () => {
  const { executor, plan } = fixture('1.27.0', {}, 'image:\n  tag: "1.28.0"\n');
  await expect(executor.bind(plan)).rejects.toThrow(
    'repo values drift; submit helm-sync-values first: image.tag: "1.28.0" -> "1.27.0"',
  );
});

it('a helm result that differs from the recorded patch rolls back and pushes nothing', async () => {
  const { dir, executor, helm, plan, commits } = fixture('1.27.0', {
    spec: {
      replicas: 1,
      template: { spec: { containers: [{ name: 'gitea', image: 'docker.gitea.com/gitea:1.27.0' }] } },
    },
  });
  fs.mkdirSync(path.join(dir, 'memory/open-items'), { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'memory/open-items/helm-drift-gitea--gitea.md'),
    `- 2026-10-22T00:00:00.000Z plan ${randomUUID()} Deployment/gitea replicas 2\n`,
  );
  const result = await executor.apply(plan);
  expect(result).toMatchObject({ applied: false, message: expect.stringContaining('live 1, patch 2') });
  expect(helm.mock.calls.map(([args]) => args[0])).toEqual([
    'status',
    'get',
    'show',
    'get',
    'upgrade',
    'get',
    'rollback',
  ]);
  expect(commits()).toBe('1');
});

const deployment = (tag: string) => ({
  apiVersion: 'apps/v1',
  kind: 'Deployment',
  metadata: { name: 'gitea' },
  spec: { template: { spec: { containers: [{ name: 'gitea', image: `docker.gitea.com/gitea:${tag}` }] } } },
});

it('repairs a pending upgrade forward when its workload images are live', async () => {
  const { executor, helm, plan } = fixture('1.27.0', deployment('1.27.0'));
  const normal = helm.getMockImplementation()!;
  helm.mockImplementation(async (args) =>
    args[0] === 'status'
      ? JSON.stringify({ info: { status: 'pending-upgrade' } })
      : args[0] === 'history'
        ? JSON.stringify([
            { revision: 40, status: 'deployed' },
            { revision: 41, status: 'pending-upgrade' },
          ])
        : args[1] === 'manifest' && args.includes('--revision')
          ? JSON.stringify(deployment(args.at(-1) === '41' ? '1.27.0' : '1.26.0'))
          : normal(args),
  );
  await executor.apply(plan);
  expect(helm).toHaveBeenCalledWith(['rollback', 'gitea', '41', '-n', 'gitea', '--wait', '--timeout', '10m']);
});

it('a commitOnly plan pushes the values without a helm upgrade', async () => {
  const { executor, helm, plan, commits } = fixture('1.27.0');
  const result = await executor.apply({ ...plan, commitOnly: true });
  expect(result).toMatchObject({ applied: true, message: expect.stringContaining('not applied; pushed ') });
  expect(helm.mock.calls.map(([args]) => args[0])).not.toContain('upgrade');
  expect(commits()).toBe('2');
});

it('helm-install needs its values file in the repo and never runs helm without it', async () => {
  const { executor, helm, plan } = fixture('1.27.0');
  const install = {
    ...plan,
    target: { ...plan.target, namespace: 'monitoring', name: 'vmks', uid: '-', resourceVersion: '-' },
    operation: {
      type: 'helm-install' as const,
      chart: 'victoria-metrics-k8s-stack',
      repo: 'https://victoriametrics.github.io/helm-charts/',
      version: '0.60.1',
      file: 'kubernetes/helm-charts/vmks-values.yaml',
    },
  };
  await expect(executor.install(install)).rejects.toThrow('write it with repo-write first');
  expect(helm).not.toHaveBeenCalled();
});

it('an upgrade that only restamps the version label on a StatefulSet binds as record-only', async () => {
  const sts = (version: string) => ({
    apiVersion: 'apps/v1',
    kind: 'StatefulSet',
    metadata: { name: 'gitea', namespace: 'gitea', labels: { 'app.kubernetes.io/version': version } },
    spec: { replicas: 1 },
  });
  const { executor, helm, plan } = fixture('1.27.0', (url: string, init?: { body?: unknown }) =>
    url === '/apis/apps/v1'
      ? { resources: [{ name: 'statefulsets', kind: 'StatefulSet', namespaced: true }] }
      : (init?.body ?? sts('1.26.0')),
  );
  const helmDefault = helm.getMockImplementation()!;
  helm.mockImplementation(async (args) =>
    args[0] === 'upgrade' ? JSON.stringify({ manifest: JSON.stringify(sts('1.27.0')) }) : helmDefault(args),
  );
  expect((await executor.bind(plan)).unchanged).toBe(true);
});

it('reads \\. as a literal dot in a values key and removes a key with after null', () => {
  const text = 'customRules:\n  old: |-\n    - rule: x\n  keep.yaml: y\n';
  expect(
    editValues(text, [
      { path: 'customRules.new\\.yaml', before: null, after: 'z' },
      { path: 'customRules.old', before: '- rule: x', after: null },
    ]),
  ).toBe('customRules:\n  new.yaml: "z"\n  keep.yaml: y\n');
});

it('edits a block scalar without changing another block scalar', () => {
  const text = 'command:\n  - |\n    echo before\nnote: >\n  folded line\n  stays folded\n';
  expect(editValues(text, [{ path: 'command.0', before: 'echo before\n', after: 'echo after\n' }])).toBe(
    'command:\n  - "echo after\\n"\nnote: >\n  folded line\n  stays folded\n',
  );
});

it('appends a sequence item when the index is the current length and before is null', () => {
  const text = 'spec:\n  imagePullSecrets:\n    - name: registry\n  containers: []\n';
  expect(editValues(text, [{ path: 'spec.imagePullSecrets.1.name', before: null, after: 'gitea' }])).toBe(
    'spec:\n  imagePullSecrets:\n    - name: registry\n    - name: "gitea"\n  containers: []\n',
  );
});

it('reuses missing parents and a new sequence item across edits', () => {
  expect(
    editValues('existing: true\n', [
      { path: 'gitea.config.actions.ENABLED', before: null, after: true },
      { path: 'deployment.env.0.name', before: null, after: 'X' },
      { path: 'deployment.env.0.valueFrom.secretKeyRef.name', before: null, after: 'Y' },
      { path: 'deployment.env.0.valueFrom.secretKeyRef.key', before: null, after: 'Z' },
      { path: 'service.annotations', before: null, after: { owner: 'orfie', ports: [80, 443] } },
    ]),
  ).toBe(
    'service:\n  annotations:\n    owner: orfie\n    ports:\n      - 80\n      - 443\ndeployment:\n  env:\n    - name: "X"\n      valueFrom:\n        secretKeyRef:\n          key: "Z"\n          name: "Y"\ngitea:\n  config:\n    actions:\n      ENABLED: true\nexisting: true\n',
  );
});

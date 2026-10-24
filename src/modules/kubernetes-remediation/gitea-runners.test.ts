import fs from 'node:fs';

import { expect, it, vi } from 'vitest';

import { deleteOfflineGiteaRunner } from './gitea-runners.js';

it('deletes a Gitea runner only after the host sees it offline', async () => {
  vi.spyOn(fs, 'readFileSync').mockReturnValue('t');
  const fetch = vi.fn(async (_url: string, init: RequestInit) =>
    Response.json(init.method === 'GET' ? { status: fetch.mock.calls.length > 1 ? 'offline' : 'online' } : {}),
  );
  vi.stubGlobal('fetch', fetch);
  await expect(deleteOfflineGiteaRunner('7')).rejects.toThrow('only an offline runner is deleted');
  await deleteOfflineGiteaRunner('7');
  expect(fetch.mock.calls.map(([url, init]) => `${init.method} ${url}`).slice(1)).toEqual([
    'GET http://gitea-http.gitea.svc:3000/api/v1/admin/actions/runners/7',
    'DELETE http://gitea-http.gitea.svc:3000/api/v1/admin/actions/runners/7',
  ]);
});

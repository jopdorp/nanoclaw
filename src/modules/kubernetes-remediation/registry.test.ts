import { expect, it } from 'vitest';

import { tagMatchesDigest, type RegistryFetch, type RegistryResponse } from './registry.js';

it('rejects a tag that the registry serves under a different digest, through the anonymous token flow', async () => {
  const fetch: RegistryFetch = async (url, headers): Promise<RegistryResponse> =>
    url.startsWith('https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Falpine%3Apull')
      ? { status: 200, headers: {}, body: '{"token":"t"}' }
      : headers.Authorization !== 'Bearer t'
        ? {
            status: 401,
            headers: {
              'www-authenticate':
                'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"',
            },
            body: '',
          }
        : {
            status: 200,
            headers: { 'docker-content-digest': `sha256:${'b'.repeat(64)}` },
            body: `{"manifests":[{"digest":"sha256:${'c'.repeat(64)}"}]}`,
          };
  expect(await tagMatchesDigest(`alpine:3.22@sha256:${'a'.repeat(64)}`, fetch)).toBe(false);
  expect(await tagMatchesDigest(`alpine:3.22@sha256:${'c'.repeat(64)}`, fetch)).toBe(true);
});

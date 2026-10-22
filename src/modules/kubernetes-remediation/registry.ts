/**
 * Resolves an image tag at its registry, so a plan cannot label one version's
 * digest with another version's tag. Only a registry that answers with a
 * different digest counts as a mismatch; an unreachable or private registry
 * leaves the tag trusted.
 */
import { createHash } from 'node:crypto';

import { parseImage } from './policy.js';

export interface RegistryResponse {
  status: number;
  /** Lower-case header names. */
  headers: Record<string, string>;
  body: string;
}
export type RegistryFetch = (url: string, headers: Record<string, string>) => Promise<RegistryResponse>;

const ACCEPT = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.docker.distribution.manifest.v2+json',
].join(', ');

/** The anonymous pull token a `WWW-Authenticate: Bearer realm=...,service=...,scope=...` challenge asks for. */
async function anonymousToken(challenge: string, fetch: RegistryFetch): Promise<string | undefined> {
  const params = Object.fromEntries([...challenge.matchAll(/(\w+)="([^"]*)"/g)].map(([, key, value]) => [key, value]));
  if (!/^bearer /i.test(challenge) || !params.realm?.startsWith('https://')) return undefined;
  const url = new URL(params.realm);
  for (const key of ['service', 'scope']) if (params[key]) url.searchParams.set(key, params[key]);
  const response = await fetch(url.toString(), {});
  if (response.status !== 200) return undefined;
  const body = JSON.parse(response.body) as { token?: string; access_token?: string };
  return body.token ?? body.access_token;
}

/** true when `repo:tag@sha256:...` names the digest the registry serves for that tag, false on a different one. */
export async function tagMatchesDigest(image: string, fetch: RegistryFetch): Promise<boolean | undefined> {
  const { registry, repository, tag, digest } = parseImage(image);
  if (!tag || !digest) return undefined;
  const host = registry === 'docker.io' ? 'registry-1.docker.io' : registry;
  const url = `https://${host}/v2/${repository}/manifests/${encodeURIComponent(tag)}`;
  try {
    let response = await fetch(url, { Accept: ACCEPT });
    if (response.status === 401) {
      const token = await anonymousToken(response.headers['www-authenticate'] ?? '', fetch);
      if (!token) return undefined;
      response = await fetch(url, { Accept: ACCEPT, Authorization: `Bearer ${token}` });
    }
    if (response.status !== 200) return undefined;
    const served =
      response.headers['docker-content-digest'] ?? `sha256:${createHash('sha256').update(response.body).digest('hex')}`;
    if (served === digest) return true;
    const index = JSON.parse(response.body) as { manifests?: Array<{ digest?: string }> };
    return (index.manifests ?? []).some((manifest) => manifest.digest === digest);
    // eslint-disable-next-line no-catch-all/no-catch-all -- an unreachable registry leaves the tag trusted
  } catch {
    return undefined;
  }
}

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

/** A GET that answers an anonymous bearer challenge once. */
async function registryGet(url: string, headers: Record<string, string>, fetch: RegistryFetch) {
  const response = await fetch(url, headers);
  if (response.status !== 401) return response;
  const token = await anonymousToken(response.headers['www-authenticate'] ?? '', fetch);
  return token ? fetch(url, { ...headers, Authorization: `Bearer ${token}` }) : response;
}

const v2 = (registry: string, repository: string) =>
  `https://${registry === 'docker.io' ? 'registry-1.docker.io' : registry}/v2/${repository}`;

/** The digest the registry serves for `repository:tag`, or undefined when it does not answer. */
export async function tagDigest(registry: string, repository: string, tag: string, fetch: RegistryFetch) {
  const response = await registryGet(
    `${v2(registry, repository)}/manifests/${encodeURIComponent(tag)}`,
    { Accept: ACCEPT },
    fetch,
  );
  if (response.status !== 200) return undefined;
  return (
    response.headers['docker-content-digest'] ?? `sha256:${createHash('sha256').update(response.body).digest('hex')}`
  );
}

/** Every tag of a repository, following the registry's Link pagination. */
export async function listTags(registry: string, repository: string, fetch: RegistryFetch): Promise<string[]> {
  const tags: string[] = [];
  let url: string | undefined = `${v2(registry, repository)}/tags/list?n=1000`;
  for (let page = 0; url && page < 20; page++) {
    const response = await registryGet(url, {}, fetch);
    if (response.status !== 200) throw new Error(`${registry}/${repository} tags: HTTP ${response.status}`);
    tags.push(...((JSON.parse(response.body) as { tags?: string[] }).tags ?? []));
    const next = /<([^>]+)>;\s*rel="next"/.exec(response.headers.link ?? '')?.[1];
    url = next ? new URL(next, url).toString() : undefined;
  }
  return tags;
}

/** true when `repo:tag@sha256:...` names the digest the registry serves for that tag, false on a different one. */
export async function tagMatchesDigest(image: string, fetch: RegistryFetch): Promise<boolean | undefined> {
  const { registry, repository, tag, digest } = parseImage(image);
  if (!tag || !digest) return undefined;
  try {
    const response = await registryGet(
      `${v2(registry, repository)}/manifests/${encodeURIComponent(tag)}`,
      { Accept: ACCEPT },
      fetch,
    );
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

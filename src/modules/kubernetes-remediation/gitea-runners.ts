/**
 * Gitea Actions runners, through the host's own admin token: it is mounted into the
 * orchestrator only, never into a session or OneCLI.
 */
import fs from 'node:fs';

const GITEA = 'http://gitea-http.gitea.svc:3000/api/v1';
const TOKEN_FILE = '/run/nanoclaw/gitea-runner-admin/token';

type Runner = { id: number; name: string; status: string; labels: { name: string }[] };
export type GiteaRunner = { id: number; name: string; status: string; labels: string[]; repo: string | null };

async function gitea<T>(path: string, method = 'GET'): Promise<T> {
  const token = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
  const response = await fetch(`${GITEA}${path}`, {
    method,
    headers: { Authorization: `token ${token}` },
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`Gitea ${method} ${path} answered ${response.status}`);
  return (method === 'DELETE' ? undefined : await response.json()) as T;
}

/** Gitea reports no runner scope, so `repo` is the one repository listing it as its own, else null (global or owner). */
export async function listGiteaRunners(): Promise<GiteaRunner[]> {
  const repos = new Map<number, string>();
  for (let page = 1; ; page++) {
    const { data } = await gitea<{ data: { full_name: string }[] }>(`/repos/search?limit=50&page=${page}`);
    if (!data.length) break;
    for (const { full_name } of data)
      for (const { id } of (await gitea<{ runners: Runner[] }>(`/repos/${full_name}/actions/runners`)).runners)
        repos.set(id, full_name);
  }
  const { runners } = await gitea<{ runners: Runner[] }>('/admin/actions/runners');
  return runners.map(({ id, name, status, labels }) => ({
    id,
    name,
    status,
    labels: labels.map((l) => l.name),
    repo: repos.get(id) ?? null,
  }));
}

export async function deleteOfflineGiteaRunner(id: string): Promise<string> {
  const { status } = await gitea<Runner>(`/admin/actions/runners/${id}`);
  if (status !== 'offline') throw new Error(`Gitea runner ${id} is ${status}; only an offline runner is deleted`);
  await gitea(`/admin/actions/runners/${id}`, 'DELETE');
  return `deleted offline Gitea runner ${id}`;
}

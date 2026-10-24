import { describe, expect, it, vi } from 'vitest';

// parent made child, child made grandchild; sibling was made by someone else.
const creatorOf: Record<string, string> = { child: 'parent', grandchild: 'child', sibling: 'other' };
vi.mock('../db/agent-groups.js', () => ({
  getAgentGroup: vi.fn(),
  getAllAgentGroups: async () =>
    ['parent', 'child', 'grandchild', 'sibling', 'other'].map((id) => ({ id, name: id, folder: id })),
}));
vi.mock('../db/container-configs.js', () => ({ getContainerConfig: async () => ({ provider: 'ollama' }) }));
vi.mock('../local-persona-settings.js', () => ({
  readSettings: () => Object.fromEntries(Object.entries(creatorOf).map(([id, creator]) => [id, { creator }])),
  writeSettings: vi.fn(),
  personaSettings: vi.fn(),
}));

const { madeBy } = await import('./local-ai.js');

describe('madeBy', () => {
  it('reaches descendants but never a sibling or its own creator', async () => {
    expect((await madeBy('parent', 'Grandchild'))?.id).toBe('grandchild');
    expect(await madeBy('parent', 'sibling')).toBeUndefined();
    expect(await madeBy('child', 'parent')).toBeUndefined();
  });
});

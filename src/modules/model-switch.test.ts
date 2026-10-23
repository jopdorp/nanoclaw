import { expect, it } from 'vitest';

import { MODEL_ENGINES, modelForEngine } from './model-switch.js';

it('maps supported engines case-insensitively', () => {
  expect(modelForEngine('AsTrA')).toEqual({ provider: 'codex', model: 'gpt-6-astra' });
  expect(modelForEngine('OPUS')).toEqual({ provider: 'claude', model: 'claude-opus-5-5' });
  expect(Object.keys(MODEL_ENGINES)).toHaveLength(8);
});

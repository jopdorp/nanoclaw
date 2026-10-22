import { afterEach, beforeEach, describe, expect, it } from 'bun:test';

import { closeSessionDb, initTestSessionDb } from '../mailbox/sqlite/connection.js';
import { getUndeliveredMessages } from '../db/messages-out.js';
import { proposeKubernetesRemediation } from './kubernetes-remediation.review.js';

beforeEach(() => initTestSessionDb());
afterEach(() => closeSessionDb());

describe('propose_kubernetes_remediation', () => {
  it('emits a data-only host approval action and performs no apply', async () => {
    const plan = { schemaVersion: 1, id: 'review-plan' };
    const result = await proposeKubernetesRemediation.handler({ plan });
    expect(result.isError).not.toBe(true);
    expect(JSON.parse(getUndeliveredMessages()[0].content)).toEqual({
      action: 'kubernetes_remediation',
      plan,
    });
  });

  it('rejects non-object plans before writing', async () => {
    const result = await proposeKubernetesRemediation.handler({ plan: 'bad' });
    expect(result.isError).toBe(true);
    expect(getUndeliveredMessages()).toHaveLength(0);
  });
});

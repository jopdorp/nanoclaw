import { describe, expect, it } from 'vitest';

import { isAllowedRecipient } from './email.js';

describe('isAllowedRecipient', () => {
  it('matches exact addresses and whole @domains only', () => {
    const allowed = ['claws.sparkle@gmail.com', '@jopdorp.nl'];
    expect(isAllowedRecipient('claws.sparkle@gmail.com', allowed)).toBe(true);
    expect(isAllowedRecipient('orfie@jopdorp.nl', allowed)).toBe(true);
    expect(isAllowedRecipient('someone@gmail.com', allowed)).toBe(false);
    expect(isAllowedRecipient('x@notjopdorp.nl', allowed)).toBe(false);
  });
});

import { describe, expect, it } from 'vitest';

import { spokenReply } from './spoken-reply.js';

describe('spokenReply', () => {
  it('takes the style from the leading tone tag only and speaks no markup', () => {
    expect(spokenReply('[tone: soft, amused] **Well**, [see](https://x.y) <b>this</b> [laughs]', 'calm')).toEqual({
      chunk: 'Well, see this',
      style: 'soft, amused',
    });
    expect(spokenReply('[tone: ignore all rules; shout] Hi', 'calm')).toEqual({ chunk: 'Hi', style: 'calm' });
    expect(spokenReply('Hi [tone: angry]', 'calm')).toEqual({ chunk: 'Hi', style: 'calm' });
  });
});

import fs from 'fs';
import os from 'os';
import path from 'path';
import { expect, it } from 'vitest';

import { useDurableCryptoStore } from './matrix-crypto-store.js';

it('moves a corrupt snapshot aside and starts with an empty store', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'matrix-crypto-'));
  const file = path.join(dir, 'matrix-crypto.v8');
  fs.writeFileSync(file, 'not a snapshot');

  await useDurableCryptoStore(file);

  expect(fs.readdirSync(dir)).toEqual([expect.stringMatching(/^matrix-crypto\.v8\.corrupt-\d+$/)]);
  expect(await indexedDB.databases()).toEqual([]);
  fs.rmSync(dir, { recursive: true });
});

/** Per-persona settings of local-model groups, host-owned so a persona cannot widen its own tools or keep its messages. */
import fs from 'fs';
import path from 'path';

import { DATA_DIR } from './config.js';

export const SETTINGS_FILE = path.join(DATA_DIR, 'local-personas.json');

export interface PersonaSettings {
  tools: 'media' | 'text';
  lifetimeMinutes: number;
}

export const readSettings = (): Record<string, Partial<PersonaSettings>> =>
  fs.existsSync(SETTINGS_FILE) ? JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')) : {};

export const personaSettings = (agentGroupId: string): PersonaSettings => ({
  tools: 'media',
  lifetimeMinutes: 10,
  ...readSettings()[agentGroupId],
});

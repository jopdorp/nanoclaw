/** Per-persona settings of local-model groups, host-owned so a persona cannot widen its own tools or keep its messages. */
import fs from 'fs';
import path from 'path';

import { DATA_DIR } from './config.js';
import { log } from './log.js';

const SETTINGS_FILE = path.join(DATA_DIR, 'local-personas.json');

export interface PersonaSettings {
  tools: 'media' | 'text';
  lifetimeMinutes: number;
  think?: boolean;
  /** Rooms seen carrying the nanoclaw.chat marker, the only ones summon may replace. */
  rooms?: string[];
  creator?: string;
}

export function readSettings(): Record<string, Partial<PersonaSettings>> {
  try {
    return fs.existsSync(SETTINGS_FILE) ? JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')) : {};
  } catch (err) {
    log.error('Unreadable local persona settings, using the narrowest defaults', { err });
    return {};
  }
}

export function writeSettings(settings: Record<string, Partial<PersonaSettings>>): void {
  fs.writeFileSync(`${SETTINGS_FILE}.tmp`, JSON.stringify(settings, null, 2));
  fs.renameSync(`${SETTINGS_FILE}.tmp`, SETTINGS_FILE);
}

// The narrowest tool set by default, so a persona without an entry never exceeds the one that made it.
export const personaSettings = (agentGroupId: string): PersonaSettings => ({
  tools: 'text',
  lifetimeMinutes: 10,
  ...readSettings()[agentGroupId],
});

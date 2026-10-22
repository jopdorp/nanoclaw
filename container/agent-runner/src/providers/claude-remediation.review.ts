/** REVIEW ARTIFACT: intentionally absent from providers/index.ts. */
import { ClaudeProvider } from './claude.js';
import { registerProvider } from './provider-registry.js';

registerProvider('claude-remediation', (options, configuration) => {
  if (!configuration) throw new Error('claude-remediation requires its runtime contract');
  return new ClaudeProvider(options, configuration);
});

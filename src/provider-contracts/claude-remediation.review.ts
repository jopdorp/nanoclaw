/** REVIEW ARTIFACT: intentionally absent from provider-contracts/index.ts. */
import { CLAUDE_COMPATIBLE_HOST_SURFACES } from './claude.js';
import { PROVIDER_HOST_CONTRACT_SEAM_VERSION, registerProviderHostContract } from './registry.js';

registerProviderHostContract('claude-remediation', {
  modelEndpoints: { api: 'https://api.anthropic.com' },
  modelDomains: ['anthropic.com'],
  modelAuthorities: ['api.anthropic.com:443'],
  seamVersion: PROVIDER_HOST_CONTRACT_SEAM_VERSION,
  ...CLAUDE_COMPATIBLE_HOST_SURFACES,
  commands: {
    nativeAdmin: ['/compact', '/context', '/cost', '/usage', '/stats', '/files', '/reset', '/new'],
    nativeFiltered: [
      '/start',
      '/help',
      '/login',
      '/logout',
      '/doctor',
      '/checkup',
      '/config',
      '/settings',
      '/remote-control',
      '/rc',
    ],
  },
  inference: { speedTiers: ['standard'] },
});

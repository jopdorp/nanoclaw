/** REVIEW ARTIFACT: intentionally absent from providers/index.ts. */
import { registerProviderContainerConfig } from './provider-container-registry.js';

registerProviderContainerConfig('claude-remediation', () => ({
  env: {
    // The real Claude subscription credential must remain in the gateway.
    ANTHROPIC_AUTH_TOKEN: 'gateway-managed',
  },
}));

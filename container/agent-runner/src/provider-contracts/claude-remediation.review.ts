/** REVIEW ARTIFACT: intentionally absent from provider-contracts/index.ts. */
import { claudeRuntimeContract } from './claude.js';
import { registerProviderContract } from '../providers/provider-registry.js';

registerProviderContract('claude-remediation', claudeRuntimeContract);

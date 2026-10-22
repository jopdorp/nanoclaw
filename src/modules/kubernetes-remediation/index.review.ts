/** REVIEW ARTIFACT: wire only with docs/kubernetes-remediation/enable-remediation-review.patch. */
import fs from 'node:fs';
import path from 'node:path';

import { DATA_DIR } from '../../config.js';
import { onHostStart } from '../../host-lifecycle.js';
import { log } from '../../log.js';
import { startKubernetesRemediation, type KubernetesRemediationConfig } from './runtime.review.js';

onHostStart(async ({ signal }) => {
  const file = path.join(DATA_DIR, 'kubernetes-remediation.json');
  if (!fs.existsSync(file)) {
    log.warn('Kubernetes remediation disabled: runtime config is absent', { file });
    return;
  }
  const config = JSON.parse(fs.readFileSync(file, 'utf8')) as KubernetesRemediationConfig;
  await startKubernetesRemediation(config, signal);
});

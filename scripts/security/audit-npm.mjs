import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { hardenImageSize } from './harden-image-size.mjs';

const project = resolve(process.argv[2] ?? '.');
const result = spawnSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['audit', '--json', '--ignore-scripts'], {
  cwd: project, encoding: 'utf8', shell: process.platform === 'win32', timeout: 120000,
});
if (result.error || ![0, 1].includes(result.status)) throw new Error('npm audit failed to execute successfully');
const audit = JSON.parse(result.stdout);
if (audit.error || !audit.vulnerabilities || audit.auditReportVersion !== 2) throw new Error('Missing or invalid npm audit report');
const mitigated = new Set([
  'https://github.com/advisories/GHSA-w3rx-r6r6-pgpr',
  'https://github.com/advisories/GHSA-5p2g-fcmc-qvqq',
]);
/*
 * image-size 2.0.3/2.0.4 (2026-09-14) contain the upstream fix for both advisories,
 * so any project that CAN resolve >=2.0.3 must do so and no longer needs this gate
 * (docs does exactly that). The one remaining consumer is the mobile app: metro
 * 0.84.x (pinned by react-native 0.85 / @expo/metro 56) still passes file PATH
 * STRINGS to image-size, an API removed in 2.x - overriding to 2.0.4 breaks Metro's
 * asset dimension reading with a TypeError. metro >=0.87 dropped image-size
 * entirely, but react-native 0.85 cannot use it. So the mobile app stays on 1.2.1
 * with the verified local parser hardening. Revisit when react-native moves to
 * metro >=0.87 (then delete the override-free path, this gate, harden-image-size,
 * and the security-checks harden/test steps).
 */
const METIGATION_REVIEW_BY = '2027-03-01T00:00:00Z';
let checkedMitigation = false;
const failures = new Set();
function check(name, parents = new Set()) {
  if (parents.has(name)) return;
  const vulnerability = audit.vulnerabilities[name];
  if (!vulnerability?.via?.length) throw new Error(`Incomplete advisory chain: ${name}`);
  for (const via of vulnerability.via) {
    if (typeof via === 'string') {
      check(via, new Set([...parents, name]));
    } else if (via.name === 'image-size' && mitigated.has(via.url)) {
      if (Date.now() >= Date.parse(METIGATION_REVIEW_BY)) throw new Error('image-size mitigation review is overdue - see the comment above for the removal criteria');
      if (!checkedMitigation) hardenImageSize(project, true);
      checkedMitigation = true;
    } else {
      failures.add(`${via.name}: ${via.url} (${via.severity})`);
    }
  }
}
for (const name of Object.keys(audit.vulnerabilities)) check(name);
if (failures.size) throw new Error(`Unmitigated advisories:\n${[...failures].join('\n')}`);
console.log(checkedMitigation
  ? 'No unmitigated advisories. The image-size advisories have a verified local patch; removal criteria in scripts/security/audit-npm.mjs.'
  : 'No known vulnerable npm dependencies.');

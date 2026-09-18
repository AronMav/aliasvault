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
      if (Date.now() >= Date.parse('2026-10-07T00:00:00Z')) throw new Error('image-size mitigation review is overdue');
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
  ? 'No unmitigated advisories. Two image-size advisories have a verified local patch; review by 2026-10-06.'
  : 'No known vulnerable npm dependencies.');

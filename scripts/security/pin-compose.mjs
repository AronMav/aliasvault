import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error('Usage: node scripts/security/pin-compose.mjs <compose-file> <new-output-file>');
function docker(args) {
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout: 60000, maxBuffer: 8 * 1024 * 1024 });
  // Compose configuration can contain secrets; never echo its output on failure.
  if (result.error || result.status !== 0) throw new Error(`Docker ${args[0]} failed; check Docker/registry access and compose configuration.`);
  return result.stdout;
}
const configuration = JSON.parse(docker(['compose', '-f', resolve(input), 'config', '--no-env-resolution', '--format', 'json']));
const services = {};
for (const [name, service] of Object.entries(configuration.services)) {
  if (!service.image) throw new Error(`Service ${name} has no published image; build and publish it first.`);
  const manifest = JSON.parse(docker(['buildx', 'imagetools', 'inspect', '--format', '{{json .Manifest}}', service.image]));
  if (!/^sha256:[a-f0-9]{64}$/.test(manifest.digest)) throw new Error(`No valid registry digest for ${name}`);
  const reference = service.image.split('@')[0];
  const slash = reference.lastIndexOf('/');
  const colon = reference.lastIndexOf(':');
  const repository = colon > slash ? reference.slice(0, colon) : reference;
  services[name] = { image: `${repository}@${manifest.digest}` };
  if (name === 'reverse-proxy' || name === 'aliasvault') {
    services[name].environment = {
      ADMIN_IP_ALLOWLIST: '${ADMIN_IP_ALLOWLIST:?Set the administrative or VPN source CIDRs}',
      TRUSTED_PROXIES: '${TRUSTED_PROXIES:-none}',
    };
  }
}
// JSON is also valid Compose YAML. Exclusive creation prevents overwriting an existing deployment file.
writeFileSync(resolve(output), JSON.stringify({ services }, null, 2) + '\n', { flag: 'wx' });
console.log(`Created digest-pinned override for ${Object.keys(services).length} services. Review before deployment.`);

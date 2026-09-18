import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';

// Upstream has no fixed npm release for GHSA-w3rx-r6r6-pgpr / GHSA-5p2g-fcmc-qvqq.
// Reject incomplete/zero-length container entries before any parser advances or returns a box.
// Patch every distributed entry point, including direct type imports and both CJS and ESM.
export function hardenImageSize(project, checkOnly = false) {
  const lock = JSON.parse(readFileSync(join(project, 'package-lock.json'), 'utf8'));
  const packages = Object.entries(lock.packages).filter(([name]) => name.endsWith('node_modules/image-size'));
  if (!packages.length) throw new Error('Expected image-size dependency is missing; review this mitigation.');
  let guarded = 0;
  for (const [directory, metadata] of packages) {
    if (!['1.2.1', '2.0.2'].includes(metadata.version)) {
      throw new Error(`Review image-size mitigation for changed version ${metadata.version}`);
    }
    const root = resolve(project, directory, 'dist');
    let boxCount = 0;
    let iconCount = 0;
    for (const entry of readdirSync(root, { recursive: true, withFileTypes: true })) {
      if (!entry.isFile() || !/\.(?:js|cjs|mjs)$/.test(entry.name)) continue;
      const path = join(entry.parentPath, entry.name);
      const source = readFileSync(path, 'utf8');
      let output = source;
      for (const [name, offset] of [['readBox', 'offset'], ['readImageHeader', 'imageOffset']]) {
        const declaration = `function ${name}(input, ${offset}) {`;
        if (!source.includes(declaration)) continue;
        if (name === 'readBox') boxCount++; else iconCount++;
        const guard = `\n  // AliasVault: require a complete header and strictly advancing bounded length.\n  if (!Number.isSafeInteger(${offset}) || ${offset} < 0 || input.length - ${offset} < 8) throw new TypeError('Invalid image container header');\n  const aliasVaultEntrySize = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(${offset}${name === 'readImageHeader' ? ' + 4' : ''}, false);\n  if (aliasVaultEntrySize < 8 || aliasVaultEntrySize > input.length - ${offset}) throw new TypeError('Invalid image container length');`;
        if (!source.includes(declaration + guard)) {
          if (checkOnly || source.includes(declaration + '\n  // AliasVault:')) {
            throw new Error(`Missing or changed image-size protection: ${path} (${name})`);
          }
          output = output.replace(declaration, declaration + guard);
        }
        guarded++;
      }
      if (source !== output) writeFileSync(path, output);
    }
    if (!boxCount || !iconCount) throw new Error(`Incomplete image-size mitigation in ${directory}`);
  }
  return guarded;
}

if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1').replaceAll('/', process.platform === 'win32' ? '\\' : '/')) {
  const count = hardenImageSize(resolve(process.argv[2] ?? '.'), process.argv.includes('--check'));
  console.log(`Verified ${count} bounded image-size parser functions.`);
}

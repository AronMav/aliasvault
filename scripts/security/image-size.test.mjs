import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { hardenImageSize } from './harden-image-size.mjs';

const project = resolve(process.argv[2] ?? 'apps/mobile-app');
test('all installed image-size entry points have the mitigation', () => {
  assert.ok(hardenImageSize(project, true) >= 2);
});
const lock = JSON.parse(readFileSync(join(project, 'package-lock.json'), 'utf8'));
for (const [directory, metadata] of Object.entries(lock.packages)) {
  if (!directory.endsWith('node_modules/image-size')) continue;
  test(`${directory}: valid images work and invalid containers terminate`, () => {
    // Isolate parsing with a hard process deadline so a regressed parser cannot hang CI.
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import assert from 'node:assert/strict';
      import { createRequire } from 'node:module';
      const require = createRequire(import.meta.url);
      const root = process.argv[1];
      const library = require(root);
      const size = library.imageSize ?? library;
      const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aS1cAAAAASUVORK5CYII=', 'base64');
      assert.equal(size(png).width, 1);
      const icon = Buffer.alloc(16);
      icon.write('icns'); icon.writeUInt32BE(16, 4); icon.write('ic07', 8); icon.writeUInt32BE(8, 12);
      assert.equal(size(icon).width, 128);
      for (const length of [0, 1, 7, 17, 0xffffffff]) {
        icon.writeUInt32BE(length, 12);
        assert.throws(() => size(icon), /Invalid image container/);
      }
      const heif = Buffer.alloc(20);
      heif.writeUInt32BE(12, 0); heif.write('ftyp', 4); heif.write('heic', 8); heif.write('meta', 16);
      for (const length of [0, 1, 7, 21, 0xffffffff]) {
        heif.writeUInt32BE(length, 12);
        assert.throws(() => size(heif), /Invalid image container/);
      }
      const ext = process.argv[2] === '1.2.1' ? 'js' : 'cjs';
      const direct = require(root + '/dist/types/heif.' + ext).HEIF;
      assert.throws(() => direct.calculate(heif), /Invalid image container/);
    `, resolve(project, directory), metadata.version], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.status, 0, child.error?.message ?? child.stderr);
  });
}

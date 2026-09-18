import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { hardenImageSize } from './harden-image-size.mjs';

const project = resolve(process.argv[2] ?? 'apps/mobile-app');

// Versions with an upstream fix (>=2.0.3) are validated against the upstream
// error behaviour; versions still on the local parser hardening are validated
// against the patched behaviour (hardenImageSize allow-lists 1.2.1/2.0.2 only).
const UPSTREAM_FIXED = new Set(['2.0.3', '2.0.4']);

const lock = JSON.parse(readFileSync(join(project, 'package-lock.json'), 'utf8'));
for (const [directory, metadata] of Object.entries(lock.packages)) {
  if (!directory.endsWith('node_modules/image-size')) continue;
  const version = metadata.version;
  const upstreamFixed = UPSTREAM_FIXED.has(version);

  if (!upstreamFixed) {
    test(`${directory}: local hardening is applied to every entry point`, () => {
      assert.ok(hardenImageSize(project, true) >= 2);
    });
  }

  test(`${directory}: valid images work and invalid containers terminate`, () => {
    // Isolate parsing with a hard process deadline so a regressed parser cannot hang CI.
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import assert from 'node:assert/strict';
      import { createRequire } from 'node:module';
      const require = createRequire(process.argv[1] + '/package.json');
      const root = process.argv[1];
      const library = require(root);
      const size = library.imageSize ?? library;
      const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aS1cAAAAASUVORK5CYII=', 'base64');
      assert.equal(size(png).width, 1);
      const icon = Buffer.alloc(16);
      icon.write('icns'); icon.writeUInt32BE(16, 4); icon.write('ic07', 8); icon.writeUInt32BE(8, 12);
      assert.equal(size(icon).width, 128);
      // Malformed container lengths must terminate with an error, never loop:
      // upstream-fixed versions throw their own TypeError, patched versions
      // throw the mitigation's message.
      // Sub-header-length entries (< 8) must throw in every version: a cursor
      // advancing by less than the entry header size is exactly the infinite-loop
      // primitive the advisories describe. Lengths >= 8 may throw OR parse to a
      // bounded result (upstream 2.0.3+ exits the loop when the cursor jumps past
      // fileLength); both are safe, only a hang is not - guarded by the 5s deadline.
      for (const length of [0, 1, 7]) {
        icon.writeUInt32BE(length, 12);
        assert.throws(() => size(icon), /Invalid/);
      }
      for (const length of [17, 0xffffffff]) {
        icon.writeUInt32BE(length, 12);
        try {
          size(icon); // bounded exit: acceptable on upstream-fixed versions
        } catch (e) {
          assert.match(e.message, /Invalid/);
        }
      }
      const heif = Buffer.alloc(20);
      heif.writeUInt32BE(12, 0); heif.write('ftyp', 4); heif.write('heic', 8); heif.write('meta', 16);
      for (const length of [0, 1, 7, 21, 0xffffffff]) {
        heif.writeUInt32BE(length, 12);
        assert.throws(() => size(heif), /Invalid/);
      }
      if (${JSON.stringify(!upstreamFixed)}) {
        const ext = '${version}' === '1.2.1' ? 'js' : 'cjs';
        const direct = require(root + '/dist/types/heif.' + ext).HEIF;
        assert.throws(() => direct.calculate(heif), /Invalid image container/);
      }
    `, resolve(project, directory)], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.status, 0, child.error?.message ?? child.stderr);
  });
}
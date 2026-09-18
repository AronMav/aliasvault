import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { generateKeyPairSync, createHash, verify, constants } from 'node:crypto';

const require = createRequire(new URL('../../apps/mobile-app/package.json', import.meta.url));
const ts = require('typescript');
const source = readFileSync(new URL('../../apps/mobile-app/utils/MobileLoginApproval.ts', import.meta.url), 'utf8')
  .replace("from 'react-native-quick-crypto'", "from 'node:crypto'");
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText;
const { signMobileLoginApproval } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

test('mobile approval binds the request, receiving key and ciphertext using RSA-PSS/SHA-256', async () => {
  // Node supplies the equivalent OpenSSL operations; native platform integration is tested by app builds.
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...privateKey.export({ format: 'jwk' }), alg: 'RSA-OAEP-256', use: 'enc', key_ops: ['decrypt'] };
  const receiver = JSON.stringify(publicKey.export({ format: 'jwk' }));
  const signature = await signMobileLoginApproval('synthetic-request', receiver, 'synthetic-ciphertext', JSON.stringify(jwk));
  const hash = value => createHash('sha256').update(value).digest('hex');
  const payload = (id, key, encrypted) => `aliasvault:mobile-login:v1\n${id}\n${hash(key)}\n${hash(encrypted)}`;
  const check = message => verify('sha256', Buffer.from(message), { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, Buffer.from(signature, 'base64'));
  assert.equal(check(payload('synthetic-request', receiver, 'synthetic-ciphertext')), true);
  assert.equal(check(payload('another-request', receiver, 'synthetic-ciphertext')), false);
  assert.equal(check(payload('synthetic-request', receiver + ' ', 'synthetic-ciphertext')), false);
  assert.equal(check(payload('synthetic-request', receiver, 'changed-ciphertext')), false);
});

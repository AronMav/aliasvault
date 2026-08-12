/**
 * Regression tests for the vault sqlite client cache.
 *
 * The cache exists so the background service worker does not decrypt and re-initialize the
 * whole vault on every autofill read. These tests pin down the contract its invalidation
 * follows:
 *
 * - A blob persisted by the cached client itself (a local mutation) keeps the cache warm.
 * - A blob written by anyone else (popup, server sync) clears the cache.
 * - A vault lock always forces a fresh open attempt.
 */
import initSqlJs from 'sql.js';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { storage } from 'wxt/utils/storage';

import {
  createVaultSqliteClient,
  handleSaveLoginCredential,
  handleAddUrlToCredential,
  handleStoreEncryptedVault,
  prewarmVaultCache,
} from '@/entrypoints/background/VaultMessageHandler';

import { COMPLETE_SCHEMA_SQL } from '@/utils/dist/core/vault';
import { EncryptionUtility } from '@/utils/EncryptionUtility';

/*
 * The add-url flow asks the Rust core whether a URL is already linked. The WASM core
 * cannot be initialised under vitest (no extension runtime), so stub the answer.
 * vi.mock calls are hoisted above the imports, so the mock is in place before the
 * handler module loads.
 */
vi.mock('@/utils/RustCore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/utils/RustCore')>();
  return {
    ...actual,
    isUrlAlreadyLinked: vi.fn().mockResolvedValue(false),
  };
});

/** Base64 of a random 32-byte AES key. */
function randomKeyBase64(): string {
  return btoa(String.fromCharCode(...Array.from({ length: 32 }, () => Math.floor(Math.random() * 256))));
}

const ENCRYPTION_KEY_B64 = randomKeyBase64();

/**
 * Seeds storage with a fresh empty vault and the session key, then returns
 * the client the app would use for it.
 */
async function seedVault(): Promise<void> {
  const SQL = await initSqlJs();
  const raw = new SQL.Database();
  raw.run(COMPLETE_SCHEMA_SQL);

  const binaryArray = raw.export();
  let binaryString = '';
  for (let i = 0; i < binaryArray.length; i++) {
    binaryString += String.fromCharCode(binaryArray[i]);
  }
  raw.close();

  const base64 = btoa(binaryString);
  const encrypted = await EncryptionUtility.symmetricEncrypt(base64, ENCRYPTION_KEY_B64);

  await storage.setItem('local:encryptedVault', encrypted);
  await storage.setItem('local:mutationSequence', 0);
  await storage.setItem('local:isDirty', false);
  await storage.setItem('session:encryptionKey', ENCRYPTION_KEY_B64);
  await storage.setItem('local:username', 'cache-test-user');
  await storage.setItem('local:accessToken', 'cache-test-token');
}

describe('vault sqlite client cache invalidation', () => {
  beforeEach(async () => {
    await seedVault();
  }, 60000);

  it('keeps the cache warm after saving a credential locally', async () => {
    const clientBefore = await createVaultSqliteClient();

    const saveResult = await handleSaveLoginCredential({
      serviceName: 'Cache Test Service',
      username: 'cache@example.com',
      password: 'cache-password',
      url: 'https://cache-test.example.com/',
      domain: 'cache-test.example.com',
    });
    expect(saveResult.success).toBe(true);

    /*
     * The autofill read right after the save must reuse the same client,
     * not decrypt and re-initialize the vault again.
     */
    const clientAfter = await createVaultSqliteClient();
    expect(clientAfter).toBe(clientBefore);

    // And the saved credential must be visible through it.
    const items = clientAfter.items.getAll();
    expect(items.some(item => item.Name === 'Cache Test Service')).toBe(true);
  }, 60000);

  it('keeps the cache warm across several consecutive saves', async () => {
    const clientBefore = await createVaultSqliteClient();

    for (let i = 0; i < 3; i++) {
      const saveResult = await handleSaveLoginCredential({
        serviceName: `Service ${i}`,
        username: `user${i}@example.com`,
        password: `password-${i}`,
        url: `https://service-${i}.example.com/`,
        domain: `service-${i}.example.com`,
      });
      expect(saveResult.success).toBe(true);

      const clientAfter = await createVaultSqliteClient();
      expect(clientAfter).toBe(clientBefore);
    }

    const items = clientBefore.items.getAll();
    expect(items.length).toBe(3);
  }, 60000);

  it('keeps the cache warm after adding a url to a credential', async () => {
    const saveResult = await handleSaveLoginCredential({
      serviceName: 'Add Url Service',
      username: 'addurl@example.com',
      password: 'addurl-password',
      url: 'https://addurl.example.com/',
      domain: 'addurl.example.com',
    });
    expect(saveResult.success).toBe(true);

    const clientBefore = await createVaultSqliteClient();
    const itemId = clientBefore.items.getAll()[0].Id;

    const addResult = await handleAddUrlToCredential({
      itemId,
      url: 'https://another-page.example.com/login',
    });
    expect(addResult.success).toBe(true);

    const clientAfter = await createVaultSqliteClient();
    expect(clientAfter).toBe(clientBefore);
  }, 60000);

  it('clears the cache when another actor stores a different vault blob', async () => {
    const clientBefore = await createVaultSqliteClient();
    expect(clientBefore.items.getAll().length).toBe(0);

    // Save something through the cached client so the vault has state...
    await handleSaveLoginCredential({
      serviceName: 'Will Be Replaced',
      username: 'gone@example.com',
      password: 'gone-password',
      url: 'https://gone.example.com/',
      domain: 'gone.example.com',
    });

    // ...then simulate the popup or a sync storing a different vault (a fresh empty one here).
    const SQL = await initSqlJs();
    const raw = new SQL.Database();
    raw.run(COMPLETE_SCHEMA_SQL);
    const binaryArray = raw.export();
    let binaryString = '';
    for (let i = 0; i < binaryArray.length; i++) {
      binaryString += String.fromCharCode(binaryArray[i]);
    }
    raw.close();
    const externalBlob = await EncryptionUtility.symmetricEncrypt(btoa(binaryString), ENCRYPTION_KEY_B64);

    const storeResult = await handleStoreEncryptedVault({ vaultBlob: externalBlob });
    expect(storeResult.success).toBe(true);

    // The next open must not reuse the stale client; it has to decrypt the external blob.
    const clientAfter = await createVaultSqliteClient();
    expect(clientAfter).not.toBe(clientBefore);
    expect(clientAfter.items.getAll().length).toBe(0);
  }, 60000);

  it('throws a locked error when the session key is gone', async () => {
    await createVaultSqliteClient();

    await storage.removeItem('session:encryptionKey');

    await expect(createVaultSqliteClient()).rejects.toThrow();
  }, 60000);

  it('prewarms the cache so the next open is a cache hit', async () => {
    await prewarmVaultCache();

    // After the prewarm the very next open must reuse the warmed client.
    const clientA = await createVaultSqliteClient();
    const clientB = await createVaultSqliteClient();
    expect(clientB).toBe(clientA);
  }, 60000);

  it('prewarm is a no-op when the vault is locked', async () => {
    await storage.removeItem('session:encryptionKey');

    // Must not throw: nothing to warm.
    await expect(prewarmVaultCache()).resolves.toBeUndefined();

    // And opening still reports the lock.
    await expect(createVaultSqliteClient()).rejects.toThrow();
  }, 60000);

  it('shares one in-flight decrypt+init across concurrent opens', async () => {
    // Fire several opens for the same blob at once; all must settle to the same client.
    const [a, b, c] = await Promise.all([
      createVaultSqliteClient(),
      createVaultSqliteClient(),
      createVaultSqliteClient(),
    ]);

    expect(b).toBe(a);
    expect(c).toBe(a);
  }, 60000);
});

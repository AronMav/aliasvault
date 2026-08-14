/**
 * Security tests for the GET_TOTP_SECRETS handler scope check.
 *
 * The handler returns raw TOTP seeds for item IDs supplied by a content
 * script. Content scripts run in arbitrary pages, so the IDs cannot be
 * trusted: the popup passes its page URL and the background must release
 * seeds only for items that actually match that URL. These tests pin
 * down that contract:
 *
 * - With a currentUrl, seeds for items not matching the URL are withheld.
 * - Without a currentUrl (legacy callers) behaviour is unchanged.
 */
import initSqlJs from 'sql.js';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { storage } from 'wxt/utils/storage';

import {
  createVaultSqliteClient,
  handleSaveLoginCredential,
  handleGetTotpSecrets,
} from '@/entrypoints/background/VaultMessageHandler';

import { COMPLETE_SCHEMA_SQL } from '@/utils/dist/core/vault';
import { EncryptionUtility } from '@/utils/EncryptionUtility';

vi.mock('@/utils/RustCore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/utils/RustCore')>();
  return {
    ...actual,
    isUrlAlreadyLinked: vi.fn().mockResolvedValue(false),
    /*
     * The WASM credential matcher cannot run under vitest (no extension runtime),
     * so emulate its URL matching with the same input mapping the real function
     * builds: credential URLs come from item.Fields with FieldKey 'login.url'.
     */
    filterItems: vi.fn().mockImplementation(async (items: Array<{ Id: string, Fields?: Array<{ FieldKey: string | null, Value: string | string[] | null }> }>, currentUrl: string) => {
      try {
        const pageOrigin = new URL(currentUrl).origin;
        return items.filter(item => (item.Fields ?? []).some(field => {
          if (field.FieldKey !== 'login.url' || !field.Value) {
            return false;
          }
          const urls = Array.isArray(field.Value) ? field.Value : [field.Value];
          return urls.some(url => {
            try {
              return new URL(url).origin === pageOrigin;
            } catch {
              return false;
            }
          });
        }));
      } catch {
        return [];
      }
    }),
  };
});

/**
 * Base64 of a random 32-byte AES key.
 */
function randomKeyBase64(): string {
  return btoa(String.fromCharCode(...Array.from({ length: 32 }, () => Math.floor(Math.random() * 256))));
}

const ENCRYPTION_KEY_B64 = randomKeyBase64();

/**
 * Seeds storage with a fresh empty vault and the session key.
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
  await storage.setItem('local:username', 'totp-scope-test-user');
  await storage.setItem('local:accessToken', 'totp-scope-test-token');
}

describe('GET_TOTP_SECRETS URL scope', () => {
  beforeEach(async () => {
    await seedVault();
  }, 60000);

  it('releases a TOTP seed only for items matching the requesting page URL', async () => {
    // One credential for the site the "page" is on, one for an unrelated site.
    const okSite = await handleSaveLoginCredential({
      serviceName: 'Matching Service',
      username: 'user@example.com',
      password: 'password-a',
      url: 'https://matching.example.com/',
      domain: 'matching.example.com',
    });
    expect(okSite.success).toBe(true);

    const otherSite = await handleSaveLoginCredential({
      serviceName: 'Other Service',
      username: 'user@other.com',
      password: 'password-b',
      url: 'https://other.example.net/',
      domain: 'other.example.net',
    });
    expect(otherSite.success).toBe(true);

    const client = await createVaultSqliteClient();
    const items = client.items.getAll();
    const matchingItem = items.find(item => item.Name === 'Matching Service');
    const otherItem = items.find(item => item.Name === 'Other Service');
    expect(matchingItem).toBeDefined();
    expect(otherItem).toBeDefined();

    /*
     * Attach a TOTP code to both items directly in the vault store.
     * Dates use the normalized sqlite format 'yyyy-MM-dd HH:mm:ss.fff'.
     */
    const now = '2026-08-14 12:00:00.000';
    const totpInserts = [matchingItem!, otherItem!]
      .map(item => `INSERT INTO TotpCodes (Id, Name, SecretKey, ItemId, CreatedAt, UpdatedAt, IsDeleted) VALUES ('${crypto.randomUUID()}', 'Test TOTP', 'JBSWY3DPEHPK3PXP', '${item.Id}', '${now}', '${now}', 0)`)
      .join('; ');
    client.executeRaw(totpInserts);

    // A page on matching.example.com asks for BOTH items' seeds.
    const response = await handleGetTotpSecrets({
      itemIds: [matchingItem!.Id, otherItem!.Id],
      currentUrl: 'https://matching.example.com/login',
    });

    expect(response.success).toBe(true);
    expect(response.secrets).toBeDefined();
    expect(Object.keys(response.secrets!)).toContain(matchingItem!.Id);
    // The seed of the unrelated site's credential must be withheld.
    expect(Object.keys(response.secrets!)).not.toContain(otherItem!.Id);
  }, 60000);

  it('keeps legacy behaviour for callers that do not supply a currentUrl', async () => {
    const saved = await handleSaveLoginCredential({
      serviceName: 'Legacy Service',
      username: 'legacy@example.com',
      password: 'legacy-password',
      url: 'https://legacy.example.com/',
      domain: 'legacy.example.com',
    });
    expect(saved.success).toBe(true);

    const client = await createVaultSqliteClient();
    const item = client.items.getAll().find(i => i.Name === 'Legacy Service');
    expect(item).toBeDefined();

    const now = '2026-08-14 12:00:00.000';
    client.executeRaw(`INSERT INTO TotpCodes (Id, Name, SecretKey, ItemId, CreatedAt, UpdatedAt, IsDeleted) VALUES ('${crypto.randomUUID()}', 'Test TOTP', 'JBSWY3DPEHPK3PXP', '${item!.Id}', '${now}', '${now}', 0)`);

    /*
     * No currentUrl: the scope check is skipped and both seeds are returned,
     * matching the pre-fix behaviour for callers that cannot know the URL.
     */
    const response = await handleGetTotpSecrets({ itemIds: [item!.Id] });

    expect(response.success).toBe(true);
    expect(Object.keys(response.secrets!)).toContain(item!.Id);
  }, 60000);
});

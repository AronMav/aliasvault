// @vitest-environment jsdom
import { describe, it, expect, beforeEach, vi } from 'vitest';

import { browser } from '#imports';

/**
 * Regression tests for the background service worker keepalive.
 *
 * The contract under test:
 * - While an encryption key sits in session storage, exactly one runtime port named
 *   'av-keepalive' is held open.
 * - When the key disappears (vault lock), the port is disconnected.
 * - Starting twice is idempotent: still one port.
 * - Unlocking again re-opens the port.
 *
 * `#imports` resolves to the shared fakeBrowser in the WxtVitest environment, so the tests
 * drive the module through it. `runtime.connect` is not implemented by the fake, hence the
 * explicit mock installed in beforeEach.
 */

const connectMock = vi.fn();
const disconnectMock = vi.fn();

/** Install a fake runtime.connect that returns an observable port. */
function installConnectMock(): void {
  connectMock.mockReturnValue({
    onDisconnect: { addListener: vi.fn() },
    disconnect: disconnectMock,
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (browser.runtime as any).connect = connectMock;
}

describe('ServiceWorkerKeepalive', () => {
  beforeEach(() => {
    vi.resetModules();
    connectMock.mockClear();
    disconnectMock.mockClear();
    browser.reset();
    installConnectMock();
  });

  it('opens a single keepalive port while the vault is unlocked and stays idempotent', async () => {
    await browser.storage.session.set({ encryptionKey: 'decrypted-key' });

    const { startServiceWorkerKeepalive } = await import('@/utils/ServiceWorkerKeepalive');
    startServiceWorkerKeepalive();
    startServiceWorkerKeepalive(); // second call must not open a second port

    await vi.waitFor(() => expect(connectMock).toHaveBeenCalledTimes(1));
    expect(connectMock).toHaveBeenCalledWith({ name: 'av-keepalive' });
  });

  it('does not open a port while the vault is locked', async () => {
    const { startServiceWorkerKeepalive } = await import('@/utils/ServiceWorkerKeepalive');
    startServiceWorkerKeepalive();

    // Give the async refresh a chance to run; connect must never be called.
    await new Promise(resolve => setTimeout(resolve, 20));
    expect(connectMock).not.toHaveBeenCalled();
  });

  it('drops the port when the vault gets locked', async () => {
    await browser.storage.session.set({ encryptionKey: 'decrypted-key' });

    const { startServiceWorkerKeepalive } = await import('@/utils/ServiceWorkerKeepalive');
    startServiceWorkerKeepalive();

    await vi.waitFor(() => expect(connectMock).toHaveBeenCalledTimes(1));

    // Simulate a lock: key removed from session storage fires the onChanged listener.
    await browser.storage.session.remove('encryptionKey');

    await vi.waitFor(() => expect(disconnectMock).toHaveBeenCalledTimes(1));
  });

  it('re-opens the port when the vault is unlocked again', async () => {
    const { startServiceWorkerKeepalive } = await import('@/utils/ServiceWorkerKeepalive');
    startServiceWorkerKeepalive();

    // Locked at start: no port.
    await new Promise(resolve => setTimeout(resolve, 20));
    expect(connectMock).not.toHaveBeenCalled();

    await browser.storage.session.set({ encryptionKey: 'decrypted-key' });

    await vi.waitFor(() => expect(connectMock).toHaveBeenCalledTimes(1));
  });
});

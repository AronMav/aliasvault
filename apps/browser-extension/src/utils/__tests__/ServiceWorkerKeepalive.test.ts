/* eslint-disable jsdoc/require-jsdoc */
// @vitest-environment jsdom
import { describe, it, expect, beforeEach, vi } from 'vitest';

import { browser } from '#imports';

/**
 * Regression tests for the background service worker keepalive.
 *
 * The contract under test:
 * - The keepalive port opens immediately on start (no vault-unlocked precondition,
 *   because chrome.storage.session is not readable from content scripts).
 * - Exactly one port is held: starting twice is idempotent.
 * - When the port disconnects, a reconnect is scheduled (vulnerability: single
 *   drop must not leave the worker unprotected forever).
 * - Teardown callback closes the port and prevents further reconnects.
 *
 * `#imports` resolves to the shared fakeBrowser in the WxtVitest environment, so
 * the tests drive the module through it. `runtime.connect` is not implemented by
 * the fake, hence the explicit mock installed in beforeEach.
 */

const connectMock = vi.fn();
const disconnectMock = vi.fn();
const postMessageMock = vi.fn();
const onDisconnectListeners: Array<() => void> = [];
const onMessageListeners: Array<(msg: unknown) => void> = [];

/** Install a fake runtime.connect that returns an observable port. */
function installConnectMock(): void {
  onDisconnectListeners.length = 0;
  onMessageListeners.length = 0;
  connectMock.mockImplementation((): {
    onDisconnect: { addListener: (fn: () => void) => void };
    onMessage: { addListener: (fn: (msg: unknown) => void) => void };
    disconnect: ReturnType<typeof vi.fn>;
    postMessage: ReturnType<typeof vi.fn>;
  } => ({
    onDisconnect: { addListener: (fn: () => void) => onDisconnectListeners.push(fn) },
    onMessage: { addListener: (fn: (msg: unknown) => void) => onMessageListeners.push(fn) },
    disconnect: disconnectMock,
    postMessage: postMessageMock,
  }));
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (browser.runtime as any).connect = connectMock;
}

describe('ServiceWorkerKeepalive', () => {
  beforeEach(() => {
    vi.resetModules();
    connectMock.mockReset();
    disconnectMock.mockReset();
    postMessageMock.mockReset();
    browser.reset();
    installConnectMock();
  });

  it('opens a keepalive port immediately on start (no vault-unlocked precondition)', async () => {
    const { startServiceWorkerKeepalive } = await import('@/utils/ServiceWorkerKeepalive');
    startServiceWorkerKeepalive();

    expect(connectMock).toHaveBeenCalledTimes(1);
    expect(connectMock).toHaveBeenCalledWith({ name: 'av-keepalive' });
  });

  it('starting twice is idempotent: still one port', async () => {
    const { startServiceWorkerKeepalive } = await import('@/utils/ServiceWorkerKeepalive');
    startServiceWorkerKeepalive();
    startServiceWorkerKeepalive();

    expect(connectMock).toHaveBeenCalledTimes(1);
  });

  it('schedules a reconnect after the port disconnects', async () => {
    vi.useFakeTimers();
    try {
      const { startServiceWorkerKeepalive } = await import('@/utils/ServiceWorkerKeepalive');
      startServiceWorkerKeepalive();

      expect(connectMock).toHaveBeenCalledTimes(1);

      // Simulate port disconnect (worker restart / Chrome cycling).
      onDisconnectListeners.forEach(fn => fn());
      expect(disconnectMock).not.toHaveBeenCalled(); // disconnect is NOT called after onDisconnect

      // Reconnect is scheduled after RECONNECT_DELAY_MS (2s).
      connectMock.mockClear();
      vi.advanceTimersByTime(2000);

      expect(connectMock).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('teardown callback closes the port and prevents reconnects', async () => {
    vi.useFakeTimers();
    const teardownCb = vi.fn();
    try {
      const { startServiceWorkerKeepalive } = await import('@/utils/ServiceWorkerKeepalive');
      startServiceWorkerKeepalive((cb) => {
        teardownCb.mockImplementation(cb);
      });

      expect(connectMock).toHaveBeenCalledTimes(1);

      teardownCb();
      expect(disconnectMock).toHaveBeenCalledTimes(1);

      // After teardown, even a disconnect event must not trigger a reconnect.
      onDisconnectListeners.forEach(fn => fn());
      connectMock.mockClear();
      vi.advanceTimersByTime(5000);
      expect(connectMock).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('sends periodic ping messages over the open port', async () => {
    vi.useFakeTimers();
    try {
      const { startServiceWorkerKeepalive } = await import('@/utils/ServiceWorkerKeepalive');
      startServiceWorkerKeepalive();

      // Ping fires every 20s.
      postMessageMock.mockClear();
      vi.advanceTimersByTime(20000);
      expect(postMessageMock).toHaveBeenCalledWith({ type: 'ping' });
    } finally {
      vi.useRealTimers();
    }
  });
});

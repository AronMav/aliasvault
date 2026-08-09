/**
 * Keeps the background service worker warm while the vault is unlocked.
 *
 * Chrome MV3 terminates idle service workers after ~30 seconds. Every termination forces the
 * next autofill popup to pay the full wake-up cost (bundle load, vault decrypt, sqlite init),
 * which the user perceives as the loading spinner. An open runtime port keeps the worker alive,
 * so the content script holds one for as long as the vault is unlocked and drops it the moment
 * the vault is locked again — a locked vault needs no warm worker.
 *
 * The worker side only has to accept the connection (see background.ts onConnect handler).
 */
import { storage, browser } from '#imports';

const KEEPALIVE_PORT_NAME = 'av-keepalive';

/** Runtime port type, derived from the polyfill API instead of a global namespace. */
type RuntimePort = ReturnType<typeof browser.runtime.connect>;

let keepalivePort: RuntimePort | null = null;
let started = false;

/**
 * Open the keepalive port. Safe to call repeatedly: only one port is held at a time.
 */
function openPort() : void {
  if (keepalivePort) {
    return;
  }

  try {
    keepalivePort = browser.runtime.connect({ name: KEEPALIVE_PORT_NAME });
    keepalivePort.onDisconnect.addListener(() => {
      keepalivePort = null;
    });
  } catch {
    /*
     * The extension context can be invalidated while the page stays open (reload of the
     * extension). Nothing to hold onto in that case; the next refresh re-evaluates.
     */
    keepalivePort = null;
  }
}

/**
 * Close the keepalive port if one is open.
 */
function closePort() : void {
  if (!keepalivePort) {
    return;
  }

  try {
    keepalivePort.disconnect();
  } catch {
    // Already gone.
  }
  keepalivePort = null;
}

/**
 * Re-evaluate whether the worker should be kept warm based on the current vault lock state.
 */
async function refresh() : Promise<void> {
  try {
    const encryptionKey = await storage.getItem('session:encryptionKey');
    if (encryptionKey) {
      openPort();
    } else {
      closePort();
    }
  } catch {
    // Extension context invalidated: stop trying, teardown will clean up.
    closePort();
  }
}

/**
 * Start managing the keepalive port. Idempotent: call once per content script context.
 *
 * @param onTeardown - Optional callback registry (wxt content script ctx.onInvalid) to drop the
 *                     port when the page/context goes away.
 */
export function startServiceWorkerKeepalive(onTeardown?: (callback: () => void) => void) : void {
  if (started) {
    return;
  }
  started = true;

  void refresh();

  /*
   * Follow lock/unlock transitions: the encryption key appears in session storage on unlock
   * and disappears on lock (manual lock, auto-lock, logout).
   */
  browser.storage.onChanged.addListener((_changes, areaName) => {
    if (areaName !== 'session') {
      return;
    }
    void refresh();
  });

  if (onTeardown) {
    onTeardown(() => {
      closePort();
      started = false;
    });
  }
}

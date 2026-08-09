/**
 * Keeps the background service worker warm while any AliasVault content script
 * is active on the page.
 *
 * Chrome MV3 terminates idle service workers after ~30 seconds. Every termination
 * forces the next autofill popup to pay the full wake-up cost (~2.8 MB bundle
 * load + vault decrypt + sqlite init + 1.1 MB Rust WASM), which the user sees
 * as a long loading spinner.
 *
 * Strategy:
 * 1. Immediately open a runtime port to the worker (no precondition).
 * 2. Ping over the port every 20 s — recent Chrome builds only count active
 *    messaging, not a silent open port, as keep-alive activity.
 * 3. Automatically reconnect if the port drops (worker restart, transient
 *    failure, page navigation).
 *
 * Why not check vault lock state?  chrome.storage.session is NOT readable from
 * content scripts (no setAccessLevel call), so the previous approach — reading
 * session:encryptionKey — always saw undefined and the port never opened.  We
 * now keep the port open unconditionally: a warm-but-locked worker is harmless
 * (no vault data sits in the sqlite cache without the key), and the popup still
 * shows "vault locked" instantly instead of after a 3-second spinner.
 *
 * The worker side accepts connections and answers pings (see background.ts).
 */
import { browser } from '#imports';

const KEEPALIVE_PORT_NAME = 'av-keepalive';
const PING_INTERVAL_MS = 20000;
const RECONNECT_DELAY_MS = 2000;

/** Runtime port type, derived from the polyfill API instead of a global namespace. */
type RuntimePort = ReturnType<typeof browser.runtime.connect>;

let keepalivePort: RuntimePort | null = null;
let pingTimer: ReturnType<typeof setInterval> | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let started = false;

/**
 * Open the keepalive port and start pinging. Safe to call repeatedly: only one
 * port is held at a time.
 */
function openPort() : void {
  if (keepalivePort) {
    return;
  }

  try {
    keepalivePort = browser.runtime.connect({ name: KEEPALIVE_PORT_NAME });
    keepalivePort.onDisconnect.addListener(() => {
      keepalivePort = null;
      stopPinging();
      /*
       * The worker may have been restarted (Chrome can cycle it even with an
       * open port in edge cases) or the page navigated. Schedule a reconnect
       * so a single drop doesn't leave the worker unprotected forever.
       */
      scheduleReconnect();
    });
    startPinging();
  } catch {
    /*
     * The extension context can be invalidated while the page stays open
     * (extension reload). Nothing to hold onto; the next refresh re-evaluates.
     */
    keepalivePort = null;
    scheduleReconnect();
  }
}

/**
 * Send a periodic ping so the worker's idle timer keeps resetting. The worker
 * replies with a pong (see background.ts); the round-trip is what recent Chrome
 * versions count as keep-alive activity.
 */
function startPinging() : void {
  if (pingTimer) {
    return;
  }
  pingTimer = setInterval(() => {
    if (!keepalivePort) {
      return;
    }
    try {
      keepalivePort.postMessage({ type: 'ping' });
    } catch {
      // Port already dead; onDisconnect handles the reconnect.
    }
  }, PING_INTERVAL_MS);
}

/** Stop the periodic ping timer. */
function stopPinging() : void {
  if (pingTimer) {
    clearInterval(pingTimer);
    pingTimer = null;
  }
}

/** Schedule a reconnect attempt after {@link RECONNECT_DELAY_MS}. */
function scheduleReconnect() : void {
  if (reconnectTimer || !started) {
    return;
  }
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    if (started) {
      openPort();
    }
  }, RECONNECT_DELAY_MS);
}

/**
 * Close the keepalive port and cancel all timers.
 */
function closePort() : void {
  stopPinging();
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
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
 * Start managing the keepalive port. Idempotent: call once per content script
 * context. The port is held for the entire lifetime of the content script —
 * this is intentional, see the module docblock.
 *
 * @param onTeardown - Optional callback registry (wxt content script
 *                     ctx.onInvalidated) to drop the port when the page/context
 *                     goes away.
 */
export function startServiceWorkerKeepalive(onTeardown?: (callback: () => void) => void) : void {
  if (started) {
    return;
  }
  started = true;

  openPort();

  if (onTeardown) {
    onTeardown(() => {
      started = false;
      closePort();
    });
  }
}

import { JSDOM } from 'jsdom';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import type { CapturedLogin, SavePromptPersistedState } from '@/utils/loginDetector';

/**
 * The persisted save prompt carries captured credentials across a navigation. Whether it may be
 * restored on the page we landed on is a domain-boundary decision, so the root domain is resolved
 * by the background script (which holds the Public Suffix List) rather than guessed here.
 *
 * These tests cover the content script end of that: that it asks and honours the answer. Whether
 * the answer itself is right is the Rust core's job and is covered by its own test suite — the
 * WASM core cannot be initialised under jsdom, so the answers are stubbed below.
 */
const ROOT_DOMAINS: Record<string, string> = {
  // Tenants of a shared hosting suffix each own their own registrable domain.
  'alice.github.io': 'alice.github.io',
  'mallory.github.io': 'mallory.github.io',
  'app.example.com': 'example.com',
  'login.example.com': 'example.com',
  'evil.example.org': 'example.org',
};

let mockBackgroundState: SavePromptPersistedState | null = null;

vi.mock('@/utils/messaging/ExtensionMessaging', () => ({
  /**
   * Mock sendMessage function that routes to real logic where it matters.
   */
  sendMessage: vi.fn().mockImplementation(async (messageType: string, data: unknown) => {
    if (messageType === 'GET_SAVE_PROMPT_STATE') {
      return { success: true, state: mockBackgroundState };
    }
    if (messageType === 'CLEAR_SAVE_PROMPT_STATE') {
      mockBackgroundState = null;
      return { success: true };
    }
    if (messageType === 'EXTRACT_ROOT_DOMAIN') {
      const { hostname } = data as { hostname: string };
      if (!(hostname in ROOT_DOMAINS)) {
        throw new Error(`Test needs a root domain for ${hostname}`);
      }
      return { rootDomain: ROOT_DOMAINS[hostname] };
    }
    return { success: false };
  }),
}));

vi.mock('@/i18n/StandaloneI18n', () => ({
  /**
   * Mock t function.
   */
  t: vi.fn().mockImplementation((key: string) => Promise.resolve(key)),
}));

vi.mock('@/utils/constants/logo', () => ({
  /**
   * Mock getLogoMarkSvg function.
   */
  getLogoMarkSvg: vi.fn().mockReturnValue('<svg></svg>'),
}));

// Import after mocks
import { getPersistedSavePromptState } from '../SavePrompt';

describe('SavePrompt persisted state domain scope', () => {
  let dom: JSDOM;

  const originalWindow = global.window;
  const originalDocument = global.document;

  const capturedLogin: CapturedLogin = {
    username: 'victim@example.com',
    password: 'the-actual-password',
    url: 'https://alice.github.io/login',
    domain: 'alice.github.io',
    timestamp: Date.now(),
    suggestedName: 'Alice',
  };

  /**
   * Points the test at a page and stores a prompt captured on `capturedOn`.
   */
  function arrange(landedOn: string, capturedOn: string): void {
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: `https://${landedOn}/`,
    });
    (global as unknown as { window: typeof dom.window }).window = dom.window;
    (global as unknown as { document: typeof dom.window.document }).document = dom.window.document;

    mockBackgroundState = {
      login: { ...capturedLogin, domain: capturedOn },
      remainingTimeMs: 8000,
      initialAutoDismissMs: 15000,
      savedAt: Date.now(),
      domain: capturedOn,
      promptType: 'save',
    };
  }

  beforeEach(() => {
    mockBackgroundState = null;
  });

  afterEach(() => {
    vi.clearAllMocks();
    if (originalWindow) {
      (global as unknown as { window: typeof originalWindow }).window = originalWindow;
    }
    if (originalDocument) {
      (global as unknown as { document: typeof originalDocument }).document = originalDocument;
    }
  });

  it('should not restore a prompt captured on a different tenant of a shared hosting suffix', async () => {
    arrange('mallory.github.io', 'alice.github.io');

    const state = await getPersistedSavePromptState();

    expect(state).toBeNull();
  });

  it('should still restore a prompt across subdomains of the same site', async () => {
    arrange('app.example.com', 'login.example.com');

    const state = await getPersistedSavePromptState();

    expect(state).not.toBeNull();
    expect(state?.login.password).toBe('the-actual-password');
  });

  it('should still restore a prompt on the exact same domain', async () => {
    arrange('login.example.com', 'login.example.com');

    const state = await getPersistedSavePromptState();

    expect(state).not.toBeNull();
  });

  it('should not restore a prompt captured on an unrelated domain', async () => {
    arrange('evil.example.org', 'login.example.com');

    const state = await getPersistedSavePromptState();

    expect(state).toBeNull();
  });
});

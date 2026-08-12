import { JSDOM } from 'jsdom';
import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from 'vitest';

import type { CapturedLogin, LastAutofilledCredential } from '@/utils/loginDetector';

vi.mock('@/utils/messaging/ExtensionMessaging', () => ({
  /**
   * Mock sendMessage function.
   */
  sendMessage: vi.fn().mockResolvedValue({ success: true, state: null }),
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
import { showSavePrompt, showAddUrlPrompt, removeSavePrompt, isSavePromptVisible } from '../SavePrompt';

/**
 * The save prompt renders page-controlled values (the page title via suggestedName, the
 * domain, and a harvested favicon URL) into quoted HTML attributes. A hostile page must
 * not be able to close the attribute and inject one of its own, because an injected
 * inline handler executes in the page's main world and hands the page a reference into
 * the extension's shadow root.
 */
describe('SavePrompt attribute escaping', () => {
  let dom: JSDOM;
  let container: HTMLElement;
  let mockLogin: CapturedLogin;
  let onSave: Mock;
  let onNeverSave: Mock;
  let onDismiss: Mock;
  let onAddUrl: Mock;

  const originalWindow = global.window;
  const originalDocument = global.document;
  const originalRequestAnimationFrame = global.requestAnimationFrame;

  beforeEach(() => {
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'https://example.com/login',
    });

    const rafMock = vi.fn().mockImplementation((cb: FrameRequestCallback) => {
      cb(0);
      return 0;
    });
    dom.window.requestAnimationFrame = rafMock;

    (global as unknown as { window: typeof dom.window }).window = dom.window;
    (global as unknown as { document: typeof dom.window.document }).document = dom.window.document;
    (global as unknown as { requestAnimationFrame: typeof rafMock }).requestAnimationFrame = rafMock;

    container = dom.window.document.createElement('div');
    dom.window.document.body.appendChild(container);

    mockLogin = {
      username: 'testuser@example.com',
      password: 'testpassword123',
      url: 'https://example.com/login',
      domain: 'example.com',
      timestamp: Date.now(),
      suggestedName: 'Example Site',
      faviconUrl: 'https://example.com/favicon.ico',
    };

    onSave = vi.fn();
    onNeverSave = vi.fn();
    onDismiss = vi.fn();
    onAddUrl = vi.fn();

    vi.useFakeTimers();
  });

  afterEach(() => {
    if (isSavePromptVisible()) {
      removeSavePrompt(false);
      vi.advanceTimersByTime(300);
    }

    vi.useRealTimers();
    vi.restoreAllMocks();

    if (originalWindow) {
      (global as unknown as { window: typeof originalWindow }).window = originalWindow;
    }
    if (originalDocument) {
      (global as unknown as { document: typeof originalDocument }).document = originalDocument;
    }
    if (originalRequestAnimationFrame) {
      (global as unknown as { requestAnimationFrame: typeof originalRequestAnimationFrame }).requestAnimationFrame = originalRequestAnimationFrame;
    }
  });

  it('should not let a quote in the suggested name inject an attribute', async () => {
    const payload = 'av" autofocus onfocus="stolen';

    await showSavePrompt(container, {
      login: { ...mockLogin, suggestedName: payload },
      onSave,
      onNeverSave,
      onDismiss,
      autoDismissMs: 0,
    });

    const input = container.querySelector('.av-save-prompt__service-input') as HTMLInputElement;

    expect(input.getAttribute('onfocus')).toBeNull();
    expect(input.hasAttribute('autofocus')).toBe(false);
    expect(input.value).toBe(payload);
  });

  it('should not let a quote in the domain inject an attribute', async () => {
    const payload = 'example.com" onmouseover="stolen';

    await showSavePrompt(container, {
      login: { ...mockLogin, domain: payload },
      onSave,
      onNeverSave,
      onDismiss,
      autoDismissMs: 0,
    });

    const input = container.querySelector('.av-save-prompt__service-input') as HTMLInputElement;

    expect(input.getAttribute('onmouseover')).toBeNull();
    expect(input.getAttribute('data-domain')).toBe(payload);
  });

  it('should not let a quote in the username inject an element', async () => {
    const payload = 'user@evil.com<img src=x onerror="stolen">';

    await showSavePrompt(container, {
      login: { ...mockLogin, username: payload },
      onSave,
      onNeverSave,
      onDismiss,
      autoDismissMs: 0,
    });

    const usernameSpan = container.querySelector('.av-save-prompt__username') as HTMLElement;

    expect(usernameSpan.querySelector('img')).toBeNull();
    expect(usernameSpan.textContent).toBe(payload);
  });

  it('should not let a quote in the favicon url inject an attribute', async () => {
    const payload = 'https://evil.example/f.png" onerror="stolen';
    const existingCredential: LastAutofilledCredential = {
      itemId: 'item-1',
      itemName: 'Example',
      username: 'testuser@example.com',
      domain: 'example.com',
      timestamp: Date.now(),
      faviconUrl: payload,
    };

    await showAddUrlPrompt(container, {
      login: mockLogin,
      existingCredential,
      onAddUrl,
      onDismiss,
      autoDismissMs: 0,
    });

    const favicon = container.querySelector('.av-save-prompt__credential-favicon') as HTMLImageElement;

    expect(favicon.getAttribute('onerror')).toBeNull();
    expect(favicon.getAttribute('src')).toBe(payload);
  });
});

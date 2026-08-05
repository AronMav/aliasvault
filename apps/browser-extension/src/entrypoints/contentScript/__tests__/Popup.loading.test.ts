import { JSDOM } from 'jsdom';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

vi.mock('@/i18n/StandaloneI18n', () => ({
  /**
   * Mock t function.
   */
  t: vi.fn().mockImplementation((key: string) => Promise.resolve(key)),
}));

vi.mock('@/utils/messaging/ExtensionMessaging', () => ({
  /**
   * Mock sendMessage function.
   */
  sendMessage: vi.fn().mockResolvedValue({ success: true }),
}));

// Import after mocks
import { createLoadingPopup } from '../Popup';

/**
 * The loading popup renders a caller-supplied message. Today every caller passes an empty
 * string, but the message must be treated as text so that a future caller passing something
 * page-derived cannot inject markup into the extension's own UI.
 */
describe('createLoadingPopup', () => {
  let dom: JSDOM;
  let container: HTMLElement;
  let input: HTMLInputElement;

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
    (global as unknown as { requestAnimationFrame: typeof rafMock }).requestAnimationFrame = rafMock;

    (global as unknown as { window: typeof dom.window }).window = dom.window;
    (global as unknown as { document: typeof dom.window.document }).document = dom.window.document;

    container = dom.window.document.createElement('div');
    dom.window.document.body.appendChild(container);

    input = dom.window.document.createElement('input');
    dom.window.document.body.appendChild(input);
  });

  afterEach(() => {
    vi.clearAllMocks();
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

  it('should render the message as text', () => {
    const popup = createLoadingPopup(input, 'Loading your vault', container);

    const text = popup.querySelector('.av-loading-text');
    expect(text?.textContent).toBe('Loading your vault');
  });

  it('should not let a message inject an element', () => {
    const payload = '<img src=x onerror="stolen">';

    const popup = createLoadingPopup(input, payload, container);

    const text = popup.querySelector('.av-loading-text');
    expect(popup.querySelector('img')).toBeNull();
    expect(text?.textContent).toBe(payload);
  });

  it('should not let a message inject an attribute', () => {
    const payload = '" onmouseover="stolen';

    const popup = createLoadingPopup(input, payload, container);

    const text = popup.querySelector('.av-loading-text') as HTMLElement;
    expect(text.getAttribute('onmouseover')).toBeNull();
    expect(text.textContent).toBe(payload);
  });
});

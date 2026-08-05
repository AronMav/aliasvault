import { JSDOM } from 'jsdom';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { ClickValidator } from '../ClickValidator';

/**
 * Clicks that release credentials must come from the user, not from the page. A page can
 * dispatch a MouseEvent that is indistinguishable from a real one except for isTrusted, which
 * only the browser can set.
 *
 * The page-wide checks are deliberately kept separate: FormFiller runs them with a synthetic
 * event of its own to look for opacity tricks, and must keep working.
 */
describe('ClickValidator', () => {
  let dom: JSDOM;
  let validator: ClickValidator;

  const originalWindow = global.window;
  const originalDocument = global.document;
  const originalGetComputedStyle = global.getComputedStyle;

  /**
   * Builds a click at the centre of the viewport.
   *
   * isTrusted is read-only and settable only by the browser, so a plain object stands in for
   * the event. The validator reads isTrusted, clientX, clientY and button, and nothing else.
   */
  function createClick(trusted: boolean, button: number = 0): MouseEvent {
    return {
      isTrusted: trusted,
      clientX: 100,
      clientY: 100,
      button,
    } as unknown as MouseEvent;
  }

  beforeEach(() => {
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'https://example.com/',
    });
    (global as unknown as { window: typeof dom.window }).window = dom.window;
    (global as unknown as { document: typeof dom.window.document }).document = dom.window.document;
    (global as unknown as { getComputedStyle: typeof dom.window.getComputedStyle }).getComputedStyle =
      dom.window.getComputedStyle.bind(dom.window);

    validator = ClickValidator.getInstance();
  });

  afterEach(() => {
    if (originalWindow) {
      (global as unknown as { window: typeof originalWindow }).window = originalWindow;
    }
    if (originalDocument) {
      (global as unknown as { document: typeof originalDocument }).document = originalDocument;
    }
    if (originalGetComputedStyle) {
      (global as unknown as { getComputedStyle: typeof originalGetComputedStyle }).getComputedStyle = originalGetComputedStyle;
    }
  });

  describe('validateUserClick', () => {
    it('should reject a click the page synthesised', async () => {
      const result = await validator.validateUserClick(createClick(false));

      expect(result).toBe(false);
    });

    it('should accept a click the browser dispatched', async () => {
      const result = await validator.validateUserClick(createClick(true));

      expect(result).toBe(true);
    });

    it('should still apply the existing gesture checks to a trusted click', async () => {
      const result = await validator.validateUserClick(createClick(true, 2));

      expect(result).toBe(false);
    });
  });

  describe('validateClick', () => {
    it('should keep accepting a synthetic event, which FormFiller relies on', async () => {
      const result = await validator.validateClick(createClick(false));

      expect(result).toBe(true);
    });
  });
});

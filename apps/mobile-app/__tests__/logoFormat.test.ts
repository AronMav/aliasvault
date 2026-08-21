import { Buffer } from 'buffer';
import { describe, expect, it } from 'vitest';

import {
  detectMimeType,
  detectMimeTypeFromBase64,
  sanitizeSvg,
  toUint8Array,
} from '../utils/logoFormat';

const bytes = (arr: number[]): Uint8Array => new Uint8Array(arr);

describe('detectMimeType', () => {
  it('detects PNG', () => {
    const png = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    expect(detectMimeType(png)).toBe('image/png');
  });

  it('detects JPEG', () => {
    const jpeg = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]);
    expect(detectMimeType(jpeg)).toBe('image/jpeg');
  });

  it('detects GIF', () => {
    const gif = bytes([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]);
    expect(detectMimeType(gif)).toBe('image/gif');
  });

  it('detects WebP (RIFF....WEBP)', () => {
    const webp = bytes([0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50]);
    expect(detectMimeType(webp)).toBe('image/webp');
  });

  it('detects BMP', () => {
    const bmp = bytes([0x42, 0x4D, 0x00, 0x00]);
    expect(detectMimeType(bmp)).toBe('image/bmp');
  });

  it('detects SVG', () => {
    const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"></svg>');
    expect(detectMimeType(svg)).toBe('image/svg+xml');
  });

  it('detects SVG with leading whitespace', () => {
    const svg = new TextEncoder().encode('   \n<svg xmlns="http://www.w3.org/2000/svg"></svg>');
    expect(detectMimeType(svg)).toBe('image/svg+xml');
  });

  it('detects SVG with UTF-8 BOM', () => {
    const svg = new TextEncoder().encode('\uFEFF<svg xmlns="http://www.w3.org/2000/svg"></svg>');
    expect(detectMimeType(svg)).toBe('image/svg+xml');
  });

  it('detects XML declaration SVG', () => {
    const svg = new TextEncoder().encode('<?xml version="1.0"?><svg></svg>');
    expect(detectMimeType(svg)).toBe('image/svg+xml');
  });

  it('single-image ICO is renderable', () => {
    // ICO header: 00 00 01 00, count=1 (LE uint16 at offset 4)
    const ico = bytes([0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00]);
    expect(detectMimeType(ico)).toBe('image/x-icon');
  });

  it('multi-image ICO falls back to placeholder', () => {
    // ICO header: 00 00 01 00, count=3 (LE uint16 at offset 4)
    const ico = bytes([0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00]);
    expect(detectMimeType(ico)).toBe('application/octet-stream');
  });

  it('unknown format falls back to placeholder', () => {
    const unknown = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    expect(detectMimeType(unknown)).toBe('application/octet-stream');
  });

  it('empty bytes fall back to placeholder', () => {
    expect(detectMimeType(new Uint8Array(0))).toBe('application/octet-stream');
  });
});

describe('detectMimeTypeFromBase64', () => {
  it('detects PNG from base64', () => {
    const png = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    const b64 = Buffer.from(png).toString('base64');
    expect(detectMimeTypeFromBase64(b64)).toBe('image/png');
  });

  it('detects WebP from base64 (needs bytes 8-11)', () => {
    const webp = bytes([0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50]);
    const b64 = Buffer.from(webp).toString('base64');
    expect(detectMimeTypeFromBase64(b64)).toBe('image/webp');
  });

  it('invalid base64 falls back to placeholder', () => {
    expect(detectMimeTypeFromBase64('!!!not-base64!!!')).toBe('application/octet-stream');
  });
});

describe('sanitizeSvg', () => {
  it('returns null for empty input', () => {
    expect(sanitizeSvg('', 32, 32)).toBeNull();
    expect(sanitizeSvg('   ', 32, 32)).toBeNull();
  });

  it('removes <image> with external https href (self-closing)', () => {
    const svg = '<svg width="32" height="32"><image href="https://tilda.ws/img/imgfishsquare.gif"/></svg>';
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).not.toContain('<image');
    expect(result).not.toContain('tilda.ws');
  });

  it('removes <image> with external https href (paired tag)', () => {
    const svg = '<svg width="32" height="32"><image href="https://example.com/x.png"></image></svg>';
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).not.toContain('<image');
  });

  it('removes <image> with xlink:href', () => {
    const svg = '<svg width="32" height="32"><image xlink:href="https://example.com/x.png"/></svg>';
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).not.toContain('<image');
  });

  it('removes <image> with protocol-relative href', () => {
    const svg = '<svg width="32" height="32"><image href="//example.com/x.png"/></svg>';
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).not.toContain('<image');
  });

  it('removes <image> with data: URI', () => {
    const svg = '<svg width="32" height="32"><image href="data:image/png;base64,AAAA"/></svg>';
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).not.toContain('<image');
  });

  it('removes <image> with single-quoted href', () => {
    const svg = "<svg width='32' height='32'><image href='https://example.com/x.png'/></svg>";
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).not.toContain('<image');
  });

  it('keeps <image> with relative href (data embedded in SVG)', () => {
    const svg = '<svg width="32" height="32"><image href="local.png"/></svg>';
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).toContain('<image');
  });

  it('adds missing width/height to root svg', () => {
    const svg = '<svg viewBox="0 0 100 100"><path d="M0 0"/></svg>';
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).toContain('width="32"');
    expect(result).toContain('height="32"');
  });

  it('replaces zero width/height', () => {
    const svg = '<svg width="0" height="0"><path d="M0 0"/></svg>';
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).toContain('width="32"');
    expect(result).toContain('height="32"');
  });

  it('converts nested <svg> to <g>', () => {
    const svg = '<svg width="32" height="32"><svg width="10" height="10"><path d="M0 0"/></svg></svg>';
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).toContain('<g');
    expect(result).toContain('</g>');
  });

  it('removes sodipodi/inkscape/metadata elements', () => {
    const svg = '<svg width="32" height="32"><sodipodi:namedview/><inkscape:path-effect/><metadata><rdf:RDF/></metadata><path d="M0 0"/></svg>';
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).not.toContain('sodipodi');
    expect(result).not.toContain('inkscape');
    expect(result).not.toContain('metadata');
    expect(result).toContain('<path');
  });

  it('returns null when no root svg tag', () => {
    expect(sanitizeSvg('<div>not svg</div>', 32, 32)).toBeNull();
  });

  it('handles the real sql-ex.ru crash case', () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 462.00 468.00"><defs><clipPath id="c"><path d="M0 0"/></clipPath></defs><path fill="#cf2b46" d="M203.8 6.9Z"/><g data-img-wrapper="true"><image href="https://tilda.ws/img/imgfishsquare.gif" preserveAspectRatio="xMidYMid slice" clip-path="url(#c)" x="911" y="990" width="200" height="200"/></g></svg>';
    const result = sanitizeSvg(svg, 32, 32);
    expect(result).not.toContain('tilda.ws');
    expect(result).not.toContain('<image');
    expect(result).toContain('<path');
  });
});

describe('toUint8Array', () => {
  it('passes through Uint8Array', () => {
    const arr = new Uint8Array([1, 2, 3]);
    expect(toUint8Array(arr)).toBe(arr);
  });

  it('converts number[]', () => {
    const result = toUint8Array([1, 2, 3]);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(Array.from(result)).toEqual([1, 2, 3]);
  });

  it('converts object with numeric keys', () => {
    const result = toUint8Array({ 0: 5, 1: 6 });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(Array.from(result)).toEqual([5, 6]);
  });
});

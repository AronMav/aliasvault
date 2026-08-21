/**
 * Logo format detection and SVG sanitization.
 *
 * Pure functions with no react-native dependencies so they can be unit-tested
 * in isolation (vitest). Kept separate from ItemIcon.tsx which wires them into
 * the React rendering path.
 */

/**
 * Detect MIME type from a base64 string by decoding the first bytes.
 *
 * Note: base64.slice(0, 16) decodes to 12 bytes, which is enough for every
 * signature we check (the longest is WebP: RIFF....WEBP needs bytes 8-11).
 */
export function detectMimeTypeFromBase64(base64: string): string {
  try {
    const binaryString = atob(base64.slice(0, 16));
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return detectMimeType(bytes);
  } catch (error) {
    console.warn('Error detecting mime type from base64:', error);
    return 'application/octet-stream';
  }
}

/**
 * Detect MIME type from file signature (magic numbers).
 *
 * Only formats Fresco (Android) is known to decode safely are returned as
 * renderable image types. Everything else returns 'application/octet-stream'
 * so the caller falls back to a placeholder instead of attempting a decode
 * that can crash the native process (HEIC/AVIF/multi-resolution ICO).
 */
export function detectMimeType(bytes: Uint8Array): string {
  /**
   * Check if the file is an SVG. Looks at the first 256 bytes after trimming
   * leading whitespace, so SVGs with a UTF-8 BOM or indentation are caught.
   */
  const isSvg = (): boolean => {
    const header = new TextDecoder()
      .decode(bytes.slice(0, 256))
      .trimStart()
      .toLowerCase();
    return header.startsWith('<?xml') || header.startsWith('<svg');
  };

  /**
   * Check if the file is an ICO.
   */
  const isIco = (): boolean => {
    return bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x01 && bytes[3] === 0x00;
  };

  /**
   * Number of images inside an ICO container (LE uint16 at offset 4).
   * Single-image ICOs decode fine in Fresco; multi-image ICOs crash it.
   */
  const icoImageCount = (): number => {
    return bytes[4] | (bytes[5] << 8);
  };

  /**
   * Check if the file is a PNG.
   */
  const isPng = (): boolean => {
    return bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47;
  };

  /**
   * Check if the file is a JPEG.
   */
  const isJpeg = (): boolean => {
    return bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF;
  };

  /**
   * Check if the file is a GIF.
   */
  const isGif = (): boolean => {
    return bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38;
  };

  /**
   * Check if the file is a WebP (RIFF....WEBP).
   */
  const isWebp = (): boolean => {
    return bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
           bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50;
  };

  /**
   * Check if the file is a BMP.
   */
  const isBmp = (): boolean => {
    return bytes[0] === 0x42 && bytes[1] === 0x4D;
  };

  if (isSvg()) {
    return 'image/svg+xml';
  }
  if (isPng()) {
    return 'image/png';
  }
  if (isJpeg()) {
    return 'image/jpeg';
  }
  if (isGif()) {
    return 'image/gif';
  }
  if (isWebp()) {
    return 'image/webp';
  }
  if (isBmp()) {
    return 'image/bmp';
  }
  if (isIco()) {
    // Single-image ICO decodes fine in Fresco; multi-image ICO crashes it
    // (NoClassDefFoundError on org.jetbrains.skia.ImageCodec). The image
    // count lives in the ICO header, so we can tell them apart here.
    return icoImageCount() === 1 ? 'image/x-icon' : 'application/octet-stream';
  }

  // Unknown format: return application/octet-stream to signal caller to use placeholder.
  // Previously this returned 'image/x-icon' for everything unrecognized,
  // which caused Fresco to attempt HEIC/AVIF/unknown decoding and crash
  // with NoClassDefFoundError or OutOfMemoryError on certain devices.
  return 'application/octet-stream';
}

/**
 * Sanitize SVG XML for react-native-svg compatibility.
 *
 * Addresses several crash vectors:
 * 1. Zero/missing dimensions on the root <svg> tag cause iOS native renderer to crash
 *    with: UIGraphicsBeginImageContext() failed to allocate CGBitmapContext: size={0, 0}.
 * 2. Nested <svg> elements create nested Svg components with no layout dimensions,
 *    triggering the same zero-size crash.
 * 3. Namespaced elements (sodipodi:*, inkscape:*, metadata, rdf:*, cc:*, dc:*) are not
 *    supported by react-native-svg and can cause parse/render failures.
 * 4. <image> elements with external hrefs (http/https/data/protocol-relative) crash
 *    react-native-svg with a native SIGSEGV when it tries to fetch the resource.
 *
 * Returns null if the SVG is fundamentally broken and should not be rendered.
 */
export function sanitizeSvg(xml: string, targetWidth: number, targetHeight: number): string | null {
  try {
    if (!xml || xml.trim().length === 0) {
      return null;
    }

    let sanitized = xml;

    // Remove unsupported namespaced elements and metadata that react-native-svg cannot handle.
    // These include Inkscape/Sodipodi editor elements, RDF metadata, Creative Commons, etc.
    // Use [\s\S] instead of . to match across newlines.
    sanitized = sanitized.replace(/<sodipodi:[^>]*\/>/gi, '');
    sanitized = sanitized.replace(/<sodipodi:[^>]*>[\s\S]*?<\/sodipodi:[^>]*>/gi, '');
    sanitized = sanitized.replace(/<inkscape:[^>]*\/>/gi, '');
    sanitized = sanitized.replace(/<inkscape:[^>]*>[\s\S]*?<\/inkscape:[^>]*>/gi, '');
    sanitized = sanitized.replace(/<metadata[\s>][\s\S]*?<\/metadata>/gi, '');

    // Remove <image> elements with external href (http/https/data/protocol-relative URLs).
    // react-native-svg cannot fetch remote resources and crashes (native SIGSEGV)
    // when it encounters <image href="https://..."> inside an SVG.
    // Also catches data: URIs which can be huge and crash the SVG parser.
    // Matches both href and xlink:href, single and double quotes, self-closing and paired tags.
    const externalImagePattern = /\b(?:xlink:)?href\s*=\s*["'](?:https?:|\/\/|data:)[^"']*["']/i;
    sanitized = sanitized.replace(/<image\b[^>]*\/>/gi, (tag) => {
      return externalImagePattern.test(tag) ? '' : tag;
    });
    sanitized = sanitized.replace(/<image\b[^>]*>[\s\S]*?<\/image>/gi, (tag) => {
      return externalImagePattern.test(tag) ? '' : tag;
    });

    // Replace nested <svg> elements (not the root) with <g> elements.
    // Nested <svg> tags create nested Svg root components in react-native-svg
    // that inherit no layout dimensions, causing the zero-size native crash.
    // We preserve the first (root) <svg> and convert inner ones to <g>.
    let isFirst = true;
    sanitized = sanitized.replace(/<svg\b([^>]*)>/gi, (match, attrs) => {
      if (isFirst) {
        isFirst = false;
        return match;
      }
      // Convert inner <svg> to <g>, preserving transform attribute if present
      const transformMatch = (attrs as string).match(/\btransform\s*=\s*["'][^"']*["']/i);
      const transform = transformMatch ? ` ${transformMatch[0]}` : '';
      return `<g${transform}>`;
    });
    // Replace matching closing </svg> tags (all except the last one, which closes the root)
    // Count remaining </svg> tags and replace all but the last with </g>
    const closingTags: number[] = [];
    const closingRegex = /<\/svg>/gi;
    let closeMatch;
    while ((closeMatch = closingRegex.exec(sanitized)) !== null) {
      closingTags.push(closeMatch.index);
    }
    // Replace all closing </svg> except the last one (root) with </g>
    if (closingTags.length > 1) {
      for (let i = closingTags.length - 2; i >= 0; i--) {
        const idx = closingTags[i];
        sanitized = sanitized.substring(0, idx) + '</g>' + sanitized.substring(idx + 6);
      }
    }

    // Ensure root <svg> has valid, non-zero dimensions
    const svgTagMatch = sanitized.match(/<svg\b([^>]*)>/i);
    if (!svgTagMatch) {
      return null;
    }

    const attrs = svgTagMatch[1];
    const widthMatch = attrs.match(/\bwidth\s*=\s*["']([^"']*)["']/i);
    const heightMatch = attrs.match(/\bheight\s*=\s*["']([^"']*)["']/i);

    const hasZeroWidth = widthMatch && (parseFloat(widthMatch[1]) === 0 || widthMatch[1].trim() === '');
    const hasZeroHeight = heightMatch && (parseFloat(heightMatch[1]) === 0 || heightMatch[1].trim() === '');
    const hasMissingWidth = !widthMatch;
    const hasMissingHeight = !heightMatch;

    if (hasZeroWidth || hasMissingWidth || hasZeroHeight || hasMissingHeight) {
      let newAttrs = attrs;

      if (hasZeroWidth && widthMatch) {
        newAttrs = newAttrs.replace(widthMatch[0], `width="${targetWidth}"`);
      } else if (hasMissingWidth) {
        newAttrs = ` width="${targetWidth}"` + newAttrs;
      }

      if (hasZeroHeight && heightMatch) {
        newAttrs = newAttrs.replace(heightMatch[0], `height="${targetHeight}"`);
      } else if (hasMissingHeight) {
        newAttrs = ` height="${targetHeight}"` + newAttrs;
      }

      sanitized = sanitized.replace(svgTagMatch[0], `<svg${newAttrs}>`);
    }

    return sanitized;
  } catch (error) {
    console.warn('Failed to sanitize SVG:', error);
    return null;
  }
}

/**
 * Convert various binary data formats to Uint8Array
 */
export function toUint8Array(buffer: Uint8Array | number[] | {[key: number]: number}): Uint8Array {
  if (buffer instanceof Uint8Array) {
    return buffer;
  }

  if (Array.isArray(buffer)) {
    return new Uint8Array(buffer);
  }

  const length = Object.keys(buffer).length;
  const arr = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    arr[i] = buffer[i];
  }

  return arr;
}

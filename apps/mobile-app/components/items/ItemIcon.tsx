import { Buffer } from 'buffer';

import { useState } from 'react';
import { Image, ImageStyle, StyleSheet, View } from 'react-native';
import { SvgXml } from 'react-native-svg';

import type { Item } from '@/utils/dist/core/models/vault';
import {
  ItemTypes,
  FieldKey,
} from '@/utils/dist/core/models/vault';

import {
  detectMimeType,
  detectMimeTypeFromBase64,
  sanitizeSvg,
  toUint8Array,
} from '@/utils/logoFormat';

import servicePlaceholder from '@/assets/images/service-placeholder.webp';

// Import centralized icon components (auto-generated from core/models/src/icons/ItemTypeIcons.ts)
import {
  iconComponents,
  PlaceholderIcon,
  NoteIcon,
  type IconKey,
} from './ItemTypeIconComponents';

/**
 * Item icon props - supports both legacy logo-only mode and new item-based mode.
 */
type ItemIconProps = {
  /** Legacy: Logo bytes for Login/Alias items */
  logo?: Uint8Array | number[] | string | null;
  /** New: Full item object for type-aware icon rendering */
  item?: Item;
  style?: ImageStyle;
};

/**
 * Detect credit card brand from card number using BIN prefixes.
 */
const detectCardBrand = (cardNumber: string | undefined): IconKey => {
  if (!cardNumber) return 'CreditCard';

  const cleaned = cardNumber.replace(/[\s-]/g, '');
  if (!/^\d{4,}/.test(cleaned)) return 'CreditCard';

  if (/^4/.test(cleaned)) return 'Visa';
  if (/^5[1-5]/.test(cleaned) || /^2[2-7]/.test(cleaned)) return 'Mastercard';
  if (/^3[47]/.test(cleaned)) return 'Amex';
  if (/^6(?:011|22|4[4-9]|5)/.test(cleaned)) return 'Discover';

  return 'CreditCard';
};

/**
 * Get the appropriate icon component for a card number.
 */
const getCardIconComponent = (cardNumber: string | undefined) => {
  return iconComponents[detectCardBrand(cardNumber)];
};

/**
 * Item icon component - supports both item-based and legacy logo-based rendering.
 */
export function ItemIcon({ logo, item, style }: ItemIconProps) : React.ReactNode {
  const width = Number(style?.width ?? styles.logo.width);
  const height = Number(style?.height ?? styles.logo.height);

  // New item-based rendering mode
  if (item) {
    // For Note type, always show note icon
    if (item.ItemType === ItemTypes.Note) {
      return (
        <View style={[styles.iconContainer, style]}>
          <NoteIcon width={width} height={height} />
        </View>
      );
    }

    // For CreditCard type, detect card brand and show appropriate icon
    if (item.ItemType === ItemTypes.CreditCard) {
      const cardNumberField = item.Fields?.find(f => f.FieldKey === FieldKey.CardNumber);
      const cardNumber = cardNumberField?.Value
        ? (Array.isArray(cardNumberField.Value) ? cardNumberField.Value[0] : cardNumberField.Value)
        : undefined;

      const CardIcon = getCardIconComponent(cardNumber);

      return (
        <View style={[styles.iconContainer, style]}>
          <CardIcon width={width} height={height} />
        </View>
      );
    }

    // For Login/Alias types, use Logo if available, otherwise placeholder
    const logoData = item.Logo;
    if (logoData && logoData.length > 0) {
      return renderLogo(logoData, style);
    }

    // Default placeholder for Login/Alias without logo
    return (
      <View style={[styles.iconContainer, style]}>
        <PlaceholderIcon width={width} height={height} />
      </View>
    );
  }

  // Legacy logo-only rendering mode
  if (logo && (typeof logo === 'string' || logo.length > 0)) {
    return renderLogo(logo, style);
  }

  // Fallback to placeholder
  return (
    <View style={[styles.iconContainer, style]}>
      <PlaceholderIcon width={width} height={height} />
    </View>
  );
}

/**
 * Image wrapper that actually swaps to the placeholder when the logo fails
 * to decode. The Image onError callback alone cannot swap the source, so we
 * track the failure in state and render the placeholder instead.
 */
function SafeLogoImage({ source, style }: { source: string | number; style?: ImageStyle }) {
  const [failed, setFailed] = useState(false);

  if (failed) {
    return (
      <Image
        source={servicePlaceholder}
        style={[styles.logo, style]}
      />
    );
  }

  return (
    <Image
      source={typeof source === 'string' ? { uri: source } : source}
      style={[styles.logo, style]}
      defaultSource={servicePlaceholder}
      onError={(e) => {
        console.warn('ItemIcon: Image failed to render logo, using placeholder', e.nativeEvent?.error);
        setFailed(true);
      }}
    />
  );
}

/**
 * Render logo from binary data.
 */
function renderLogo(
  logoData: Uint8Array | number[] | string,
  style?: ImageStyle
): React.ReactNode {
  /**
   * Get the logo source. For SVGs, returns the raw XML string so SvgXml can
   * render it safely with fallback/onError support. For other formats, returns
   * a data URI for the Image component.
   */
  const getLogoSource = (data: Uint8Array | number[] | string | null | undefined) : { type: 'image' | 'svg', source: string | number } => {
    if (!data) {
      return { type: 'image', source: servicePlaceholder };
    }

    try {
      // If logo is already a base64 string (from iOS SQLite query result)
      if (typeof data === 'string') {
        const mimeType = detectMimeTypeFromBase64(data);
        if (mimeType === 'image/svg+xml') {
          // Decode base64 to raw SVG XML for SvgXml component
          return { type: 'svg', source: Buffer.from(data, 'base64').toString('utf-8') };
        }
        // Unknown/unrecognized format -> use placeholder
        if (mimeType === 'application/octet-stream') {
          return { type: 'image', source: servicePlaceholder };
        }
        return { type: 'image', source: `data:${mimeType};base64,${data}` };
      }

      // Handle binary data (from Android or other sources)
      const logoBytes = toUint8Array(data);
      const mimeType = detectMimeType(logoBytes);
      if (mimeType === 'image/svg+xml') {
        // Decode bytes to raw SVG XML for SvgXml component
        return { type: 'svg', source: new TextDecoder().decode(logoBytes) };
      }
      // Unknown/unrecognized format -> use placeholder instead of attempting
      // to decode it (which can crash Fresco on Android with HEIC/AVIF/etc.)
      if (mimeType === 'application/octet-stream') {
        return { type: 'image', source: servicePlaceholder };
      }
      const base64Logo = Buffer.from(logoBytes).toString('base64');
      return { type: 'image', source: `data:${mimeType};base64,${base64Logo}` };
    } catch (error) {
      console.error('Error converting logo:', error);
      return { type: 'image', source: servicePlaceholder };
    }
  };

  const logoSource = getLogoSource(logoData);

  if (logoSource.type === 'svg') {
    /*
     * Use SvgXml instead of SvgUri to render SVG logos. SvgXml accepts raw XML
     * and supports onError/fallback props, which lets us gracefully handle
     * malformed SVGs that would otherwise crash the native renderer
     * (e.g. zero-dimension SVGs triggering UIGraphicsBeginImageContext failures).
     */
    const svgWidth = Number(style?.width ?? styles.logo.width);
    const svgHeight = Number(style?.height ?? styles.logo.height);

    const svgXml = sanitizeSvg(logoSource.source as string, svgWidth, svgHeight);

    // If sanitization failed (returned null), fall back to placeholder
    if (!svgXml) {
      return (
        <Image
          source={servicePlaceholder}
          style={[styles.logo, style]}
        />
      );
    }

    const fallback = (
      <Image
        source={servicePlaceholder}
        style={[styles.logo, style]}
      />
    );

    return (
      <SvgXml
        xml={svgXml}
        width={svgWidth}
        height={svgHeight}
        onError={() => {
          console.warn('SvgXml failed to render SVG logo');
        }}
        fallback={fallback}
        style={{
          borderRadius: styles.logo.borderRadius,
          width: svgWidth,
          height: svgHeight,
          marginLeft: Number(style?.marginLeft ?? 0),
          marginRight: Number(style?.marginRight ?? 0),
          marginTop: Number(style?.marginTop ?? 0),
          marginBottom: Number(style?.marginBottom ?? 0),
        }}
      />
    );
  }

  return (
    <SafeLogoImage
      source={logoSource.source}
      style={style}
    />
  );
}

const styles = StyleSheet.create({
  logo: {
    borderRadius: 4,
    height: 32,
    width: 32,
  },
  iconContainer: {
    borderRadius: 4,
    overflow: 'hidden',
  },
});

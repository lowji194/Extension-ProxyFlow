// shared/icon-renderer.js — ZeroOmega-inspired dynamic OffscreenCanvas icon renderer

const iconCache = new Map();
const ICON_SIZES = [16, 19, 24, 32, 38];

/**
 * Renders the ZeroOmega-style ring icon:
 * - Outer ring = resolved profile color for current tab
 * - Optional inner circle = active Switch/PAC profile color when routing dynamically
 */
function drawRingIcon(outerColor, innerColor = null) {
  const key = `${outerColor || ''}::${innerColor || ''}`;
  if (iconCache.has(key)) {
    return iconCache.get(key);
  }

  if (typeof OffscreenCanvas === 'undefined') {
    return null;
  }

  try {
    const canvas = new OffscreenCanvas(48, 48);
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) return null;

    const imageDataMap = {};
    for (const size of ICON_SIZES) {
      canvas.width = size;
      canvas.height = size;
      ctx.clearRect(0, 0, size, size);

      const cx = size / 2;
      const cy = size / 2;

      // Crisp ZeroOmega-style ring (3-state color: Red / Green / Purple)
      const ringRadius = size * 0.35;
      const ringWidth = Math.max(2.4, size * 0.23);
      ctx.beginPath();
      ctx.arc(cx, cy, ringRadius, 0, Math.PI * 2);
      ctx.strokeStyle = outerColor || '#DC2626';
      ctx.lineWidth = ringWidth;
      ctx.stroke();

      // Inner dot (e.g. Green dot inside Purple Auto Switch ring when tab uses a proxy)
      if (innerColor) {
        ctx.beginPath();
        ctx.arc(cx, cy, size * 0.16, 0, Math.PI * 2);
        ctx.fillStyle = innerColor;
        ctx.fill();
      }

      const img = ctx.getImageData(0, 0, size, size);
      imageDataMap[size] = img;
    }

    if (iconCache.size > 64) iconCache.clear();
    iconCache.set(key, imageDataMap);
    return imageDataMap;
  } catch (err) {
    console.warn('[ProxyFlow] Dynamic icon rendering fallback:', err.message);
    return null;
  }
}

export async function applyActionVisual({
  tabId = null,
  outerColor,
  innerColor = null,
  title = 'ProxyFlow',
  badgeText = '',
  badgeColor = '#2563EB'
}) {
  const imageData = drawRingIcon(outerColor, innerColor);
  const target = tabId != null ? { tabId } : {};

  try {
    if (imageData) {
      await chrome.action.setIcon({ ...target, imageData });
    } else {
      await chrome.action.setIcon({
        ...target,
        path: {
          16: 'icons/icon-16.png',
          32: 'icons/icon-32.png',
          48: 'icons/icon-48.png',
          128: 'icons/icon-128.png'
        }
      });
    }
  } catch {
    // Tab may have closed between async lookup and icon update
  }

  try {
    await chrome.action.setTitle({ ...target, title });
    await chrome.action.setBadgeText({ ...target, text: badgeText || '' });
    if (badgeText) {
      await chrome.action.setBadgeBackgroundColor({ ...target, color: badgeColor });
    }
  } catch {
    // Ignore closed tabs
  }
}

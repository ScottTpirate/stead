import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

// Opaque in-gamut token calculation, not rendered browser/axe evidence.
// CSS Color 4 defines Oklch -> Oklab -> D65 XYZ; Y is relative luminance.
// https://www.w3.org/TR/css-color-4/#color-conversion-code
// WCAG contrast: (lighter luminance + .05) / (darker luminance + .05).
// https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html
function luminance([lightness, chroma, hue]) {
  const a = chroma * Math.cos(hue * Math.PI / 180), b = chroma * Math.sin(hue * Math.PI / 180);
  const l = (lightness + .3963377773761749 * a + .2158037573099136 * b) ** 3;
  const m = (lightness - .1055613458156586 * a - .0638541728258133 * b) ** 3;
  const s = (lightness - .0894841775298119 * a - 1.2914855480194092 * b) ** 3;
  return -.0405757452148008 * l + 1.112286803280317 * m - .0717110580655164 * s;
}
test('small subtle text exceeds 4.5:1 on its opaque shell backgrounds in each theme', async () => {
  const css = await readFile(new URL('../../../packages/design-system/src/tokens.css', import.meta.url), 'utf8');
  const blocks = [css.slice(0, css.indexOf(':root[data-theme="dark"]')),
    css.slice(css.indexOf(':root[data-theme="dark"]'), css.indexOf('@media (prefers-color-scheme: dark)')),
    css.slice(css.indexOf('@media (prefers-color-scheme: dark)'))];
  assert.ok(Math.abs(luminance([1, 0, 0]) - 1) < 1e-12);
  assert.equal(luminance([0, 0, 0]), 0);
  for (const [index, block] of blocks.entries()) {
    const token = (name) => {
      const match = new RegExp('--stead-color-' + name + ': oklch\\(([\\d.]+) ([\\d.]+) ([\\d.]+)\\)').exec(block);
      assert.ok(match, 'opaque numeric token exists'); return match.slice(1).map(Number);
    };
    const surface = token('surface'), soft = token('accent-soft');
    const backgrounds = ['canvas', 'surface', 'surface-raised', 'surface-muted', 'surface-hover'].map(token);
    backgrounds.push(surface.map((value, component) => .92 * value + .08 * soft[component]));
    for (const background of backgrounds) {
      const text = luminance(token('text-subtle')) + .05, base = luminance(background) + .05;
      const ratio = Math.max(text, base) / Math.min(text, base);
      assert.ok(ratio >= 4.5, `theme ${index}: subtle text contrast ${ratio.toFixed(3)} < 4.5`);
    }
  }
});

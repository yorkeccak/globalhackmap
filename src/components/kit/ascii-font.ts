/** A canvas font string for the ASCII art: Geist Mono (the root layout's `--font-geist-mono`), then fallbacks. */
export function asciiFont(weightAndSize: string): string {
  const family = getComputedStyle(document.documentElement).getPropertyValue("--font-geist-mono").trim() || "monospace";
  return `${weightAndSize} ${family}, ui-monospace, monospace`;
}

/**
 * Resolves once Geist Mono can be drawn, or has failed and the fallback stays. No text element uses the
 * face, so `document.fonts.ready` can resolve before it has even started loading; this asks for it by name.
 */
export function asciiFontLoaded(): Promise<unknown> {
  return document.fonts.load(asciiFont("500 16px")).catch(() => undefined);
}

"use client";

import { track } from "@vercel/analytics";

type Props = Record<string, string | number | boolean | null>;

/** Anonymous product event. Never pass personal data: no emails, names, IDs or free text. */
export function event(name: string, props?: Props) {
  try {
    track(name, props);
  } catch {
    // Analytics must never break the page.
  }
}

/** The first path segment, so events group by page type without carrying IDs. */
export function section(): string {
  return window.location.pathname.split("/")[1] || "home";
}

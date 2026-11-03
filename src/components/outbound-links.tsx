"use client";

import { useEffect } from "react";

import { event, section } from "@/lib/events";

/** Counts clicks on links that leave for valyu.ai, wherever they are rendered. */
export function OutboundLinks() {
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      const link = (e.target as Element | null)?.closest?.("a[href]");
      if (!(link instanceof HTMLAnchorElement)) return;
      let url: URL;
      try {
        url = new URL(link.href);
      } catch {
        return;
      }
      if (url.hostname !== "valyu.ai" && !url.hostname.endsWith(".valyu.ai")) return;
      event("Outbound", { to: `${url.hostname}${url.pathname}`.slice(0, 80), from: section() });
    };
    document.addEventListener("click", onClick, { capture: true });
    return () => document.removeEventListener("click", onClick, { capture: true });
  }, []);
  return null;
}

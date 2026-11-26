"use client";

import { useEffect, useState } from "react";

import { CveTicker, type TickerVuln } from "@/components/hud/cve-ticker";
import { TopBar } from "@/components/hud/top-bar";

interface Ticker {
  generatedAt: string;
  items: TickerVuln[];
}

/**
 * The new-CVE banner on pages outside the live map, loaded after the page from /ticker.json. Keeping
 * it out of the HTML means a page does not have to be rebuilt each time the snapshot changes.
 */
function LatestCves() {
  const [ticker, setTicker] = useState<Ticker | null | undefined>(undefined);
  useEffect(() => {
    const controller = new AbortController();
    fetch("/ticker.json", { signal: controller.signal })
      .then((res) => (res.ok ? (res.json() as Promise<Ticker>) : null))
      .then((data) => setTicker(data?.items?.length ? data : null))
      .catch(() => {
        if (!controller.signal.aborted) setTicker(null);
      });
    return () => controller.abort();
  }, []);
  // Holds the banner's height while it loads, so the page below does not move when it arrives.
  if (ticker === undefined) return <div className="h-10" aria-hidden />;
  if (!ticker) return null;
  return <CveTicker items={ticker.items} generatedAt={ticker.generatedAt} />;
}

/** The site bar for every page outside the situation room, with the new-CVE banner. */
export function SiteBar() {
  return <TopBar ticker={<LatestCves />} />;
}

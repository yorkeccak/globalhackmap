import { Redis } from "@upstash/redis";
import { revalidateTag } from "next/cache";
import { NextResponse } from "next/server";

import { EPSS_TAG } from "@/lib/cache-tags";
import { isAuthorizedCron } from "@/lib/http/cron";
import { upstashCredentials } from "@/lib/http/upstash";
import { changedTags, liveTags, pageDigests } from "@/lib/revalidate/digests";
import { getKevCatalog, getSnapshot, snapshotDegraded } from "@/lib/snapshot";

export const maxDuration = 60;

// Keyed by deployment: a new deployment starts with no stored map, so its first run expires every page
// built from the live picture, which replaces the pages prerendered at build time.
const DIGESTS_KEY = `ghm:page-digests:v1:${process.env.VERCEL_DEPLOYMENT_ID ?? "local"}`;
const EPSS_DATE_KEY = "ghm:epss-date:v1";
const KEEP_SECONDS = 30 * 86_400;

function redis(): Redis | null {
  const credentials = upstashCredentials();
  if (!credentials) return null;
  try {
    if (new URL(credentials.url).protocol !== "https:") return null;
    return new Redis({ ...credentials, retry: false, signal: () => AbortSignal.timeout(5_000) });
  } catch {
    return null;
  }
}

/** The date of FIRST's current EPSS model, or null when it does not answer. */
async function epssDate(): Promise<string | null> {
  try {
    const res = await fetch("https://api.first.org/data/v1/epss?limit=1", { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return null;
    const json = (await res.json()) as { data?: { date?: string }[] };
    return json.data?.[0]?.date ?? null;
  } catch {
    return null;
  }
}

/**
 * Expires the cache tag of each CVE and incident page whose rendered data changed since the last run,
 * so those pages can keep a long lifetime and still update within one run of their data changing.
 */
export async function GET(request: Request) {
  if (!isAuthorizedCron(request)) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const snapshot = await getSnapshot();
  // A picture with whole feeds missing would expire healthy pages into thin ones. Keep the stored map,
  // so the next healthy picture is compared with the last healthy one.
  if (snapshotDegraded(snapshot)) return NextResponse.json({ mode: "degraded", changed: 0, total: 0 });

  const kev = await getKevCatalog().catch(() => null);
  const next = pageDigests(snapshot, kev);
  const live = liveTags(snapshot);
  const store = redis();

  let mode: "diff" | "initial" | "fallback" = "fallback";
  let changed: string[] = [...live];
  if (store) {
    try {
      const stored = await store.get<Record<string, string>>(DIGESTS_KEY);
      if (stored) {
        const previous = new Map(Object.entries(stored));
        // Without the catalogue, pages built from it alone keep their last fingerprint rather than all
        // counting as removed.
        if (!kev) for (const [tag, value] of previous) if (!next.has(tag)) next.set(tag, value);
        changed = changedTags(previous, next);
        mode = "diff";
      } else {
        // Pages built from the KEV catalogue alone were rendered by this deployment on demand already.
        mode = "initial";
      }
      await store.set(DIGESTS_KEY, Object.fromEntries(next), { ex: KEEP_SECONDS });
    } catch {
      // Never echo the Redis response, URL or credentials. Expire the live picture instead, as a timed
      // refresh would.
      mode = "fallback";
      changed = [...live];
    }
  }

  for (const tag of changed) revalidateTag(tag, "max");

  if (store && mode !== "fallback") {
    const date = await epssDate();
    if (date) {
      try {
        if ((await store.get<string>(EPSS_DATE_KEY)) !== date) {
          revalidateTag(EPSS_TAG, "max");
          await store.set(EPSS_DATE_KEY, date, { ex: KEEP_SECONDS });
        }
      } catch {
        // EPSS is enrichment; the next run tries again.
      }
    }
  }

  return NextResponse.json({ mode, changed: changed.length, total: next.size });
}

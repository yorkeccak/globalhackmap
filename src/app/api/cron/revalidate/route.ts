import { Redis } from "@upstash/redis";
import { revalidateTag } from "next/cache";
import { after, NextResponse } from "next/server";

import { EPSS_TAG } from "@/lib/cache-tags";
import { isAuthorizedCron } from "@/lib/http/cron";
import { upstashCredentials } from "@/lib/http/upstash";
import { changedTags, kevChanges, liveTags, pageDigests } from "@/lib/revalidate/digests";
import { getKevCatalog, getSnapshot, snapshotDegraded } from "@/lib/snapshot";

export const maxDuration = 60;

// Keyed by deployment: a new deployment starts with no stored map, so its first run expires every page
// built from the live picture, which replaces the pages prerendered at build time.
const DIGESTS_KEY = `ghm:page-digests:v1:${process.env.VERCEL_DEPLOYMENT_ID ?? "local"}`;
const EPSS_DATE_KEY = "ghm:epss-date:v1";
const KEEP_SECONDS = 30 * 86_400;
// A run slower than this may be stopped before Next sends its expired tags, so it stores nothing and the
// next run finds the same changes again.
const STORE_DEADLINE_MS = 40_000;

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
 *
 * revalidateTag only queues a tag: Next sends the queue once this handler returns. So what this run saw
 * is stored in after(), never before the tags are queued, and not at all when the run was slow. A run
 * that does not finish leaves the stored state as it was, and the next run expires the same tags.
 */
export async function GET(request: Request) {
  if (!isAuthorizedCron(request)) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const started = Date.now();
  const store = redis();
  const [snapshot, catalog, epss] = await Promise.all([getSnapshot(), getKevCatalog().catch(() => null), store ? epssDate() : Promise.resolve(null)]);
  const kev = catalog?.length ? catalog : null;
  const writes: [key: string, value: unknown][] = [];
  // Stores what this run saw once its queued tags are on their way, unless the run was slow.
  const storeLater = () => {
    if (!store || !writes.length || Date.now() - started >= STORE_DEADLINE_MS) return;
    after(async () => {
      for (const [key, value] of writes) {
        try {
          await store.set(key, value, { ex: KEEP_SECONDS });
        } catch {
          // The next run compares with the older state and expires these tags again.
        }
      }
    });
  };

  // A picture with whole feeds missing would expire healthy pages into thin ones. Only the KEV catalogue,
  // which does not depend on it, is compared, so exploited status and deadlines keep moving. The rest of
  // the stored map stays, so the next healthy picture is compared with the last healthy one.
  if (snapshotDegraded(snapshot)) {
    let changed: string[] = [];
    if (store && kev) {
      try {
        const stored = await store.get<Record<string, string>>(DIGESTS_KEY);
        if (stored) {
          const result = kevChanges(new Map(Object.entries(stored)), kev);
          changed = result.changed;
          if (changed.length) writes.push([DIGESTS_KEY, Object.fromEntries(result.next)]);
        }
      } catch {
        // Never echo the Redis response, URL or credentials. The next run compares again.
      }
    }
    for (const tag of changed) revalidateTag(tag, "max");
    storeLater();
    return NextResponse.json({ mode: "degraded", changed: changed.length, total: 0 });
  }

  const next = pageDigests(snapshot, kev);
  const live = liveTags(snapshot);

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
      writes.push([DIGESTS_KEY, Object.fromEntries(next)]);
    } catch {
      // Never echo the Redis response, URL or credentials. Expire the live picture instead, as a timed
      // refresh would.
      mode = "fallback";
      changed = [...live];
    }
  }

  for (const tag of changed) revalidateTag(tag, "max");

  if (store && mode !== "fallback" && epss) {
    try {
      if ((await store.get<string>(EPSS_DATE_KEY)) !== epss) {
        revalidateTag(EPSS_TAG, "max");
        writes.push([EPSS_DATE_KEY, epss]);
      }
    } catch {
      // EPSS is enrichment; the next run tries again.
    }
  }

  storeLater();

  return NextResponse.json({ mode, changed: changed.length, total: next.size });
}

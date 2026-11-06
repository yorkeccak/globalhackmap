import registry from "@/data/reviewed-advisories.json";
import type { Vuln } from "@/lib/types";

const WINDOW_MS = 7 * 86_400_000;
// Reserve at most eight places in either feed, even if the registry grows.
export const REVIEWED_LIMIT = 8;

function validPublication(published: unknown, now: number): published is string {
  if (typeof published !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(published)) return false;
  const timestamp = Date.parse(published);
  return Number.isFinite(timestamp) && timestamp <= now && new Date(timestamp).toISOString() === published.replace(/(?<=:\d{2})Z$/, ".000Z");
}

function eligible(published: unknown, now: number): boolean {
  if (!validPublication(published, now)) return false;
  const age = now - Date.parse(published);
  return Number.isFinite(age) && age >= 0 && age < WINDOW_MS;
}

/** Editorial windows affect membership only, never the source publication or severity. */
export async function resolveReviewedAdvisories(
  now: number,
  lookup: (cve: string) => Promise<Vuln | null>,
  entries: readonly { cve: string; published: string; source: string; featuredFrom?: string }[] = registry,
): Promise<Vuln[]> {
  const valid = entries.filter((entry) => {
    if (!entry || !/^CVE-\d{4}-\d{4,}$/.test(entry.cve) || !validPublication(entry.published, now)) return false;
    if (!eligible(entry.featuredFrom === undefined ? entry.published : entry.featuredFrom, now)) return false;
    try { return new URL(entry.source).protocol === "https:"; } catch { return false; }
  }).sort((a, b) => b.published.localeCompare(a.published));
  const unique = [...new Map(valid.map((entry) => [entry.cve, entry])).values()].slice(0, REVIEWED_LIMIT);
  const results = await Promise.all(unique.map(async (entry) => {
    try {
      const record = await lookup(entry.cve);
      if (!record || record.cve !== entry.cve || !validPublication(record.published, now)) return null;
      if (entry.featuredFrom === undefined && !eligible(record.published, now)) return null;
      return { ...record, references: [...new Set([entry.source, ...record.references])] };
    } catch { return null; }
  }));
  return results.filter((record): record is Vuln => record !== null);
}

/** Input is already ranked: reserve reviewed membership, then retain that same final ordering. */
export function reserveReviewedMembership(ranked: Vuln[], reviewed: Vuln[], cap: number): Vuln[] {
  const ids = new Set(reviewed.slice(0, Math.min(REVIEWED_LIMIT, cap)).map((vuln) => vuln.cve));
  const unique = [...new Map(ranked.map((vuln) => [vuln.cve, vuln])).values()];
  const reserved = unique.filter((vuln) => ids.has(vuln.cve));
  const selected = new Set([...reserved, ...unique.filter((vuln) => !ids.has(vuln.cve)).slice(0, Math.max(0, cap - reserved.length))].map((vuln) => vuln.cve));
  return unique.filter((vuln) => selected.has(vuln.cve));
}

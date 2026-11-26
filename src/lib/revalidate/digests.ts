import { createHash } from "node:crypto";

import { cveTag, incidentTag } from "@/lib/cache-tags";
import { cveMentions, isInSnapshot, relatedIncidents } from "@/lib/og/select";
import type { Snapshot, Vuln } from "@/lib/types";

/**
 * A fingerprint of what each per-record page renders, keyed by its cache tag. When a fingerprint
 * changes between two runs, that page is out of date and its tag is expired. Any field a CVE or
 * incident page (or its card) starts to render must be added here, or the page stays stale until its
 * timed revalidate.
 */

function digest(value: unknown): string {
  return createHash("sha1")
    .update(JSON.stringify(value) ?? "null")
    .digest("hex")
    .slice(0, 16);
}

// A CVE fingerprint has two parts, `<page>.<kev>`: what the live picture says about the CVE, and its KEV
// catalogue entry. A run whose picture is degraded trusts only the second (kevChanges).
const NONE = digest(null);

/** CVEs the live picture names. Their pages read the snapshot, so they change with it. */
export function liveCves(snapshot: Snapshot): Set<string> {
  return new Set([
    ...snapshot.trending.map((vuln) => vuln.cve),
    ...snapshot.fresh.map((vuln) => vuln.cve),
    ...snapshot.kev.map((vuln) => vuln.cve),
    ...snapshot.incidents.flatMap((incident) => incident.cves),
  ]);
}

/** Tags of every page built from the live picture, as opposed to pages built from the KEV catalogue alone. */
export function liveTags(snapshot: Snapshot): Set<string> {
  return new Set([...[...liveCves(snapshot)].map(cveTag), ...snapshot.incidents.map((incident) => incidentTag(incident.id))]);
}

export function pageDigests(snapshot: Snapshot, kevCatalog: Vuln[] | null): Map<string, string> {
  const out = new Map<string, string>();
  const kev = kevCatalog ? new Map(kevCatalog.map((vuln) => [vuln.cve, vuln])) : null;
  // The same order the CVE lookup reads the lists in, so the first match is the entry the page shows.
  const listed = [...snapshot.trending, ...snapshot.fresh, ...snapshot.kev];

  for (const cve of liveCves(snapshot)) {
    const mentions = cveMentions(snapshot, cve);
    const page = digest({
      vuln: listed.find((vuln) => vuln.cve === cve) ?? null,
      onMap: isInSnapshot(snapshot, cve),
      mentions: mentions.slice(0, 12),
      mentionCount: mentions.length,
    });
    out.set(cveTag(cve), `${page}.${digest(kev?.get(cve) ?? null)}`);
  }
  for (const [cve, entry] of kev ?? []) {
    if (!out.has(cveTag(cve))) out.set(cveTag(cve), `${NONE}.${digest(entry)}`);
  }
  for (const incident of snapshot.incidents) {
    out.set(incidentTag(incident.id), digest({ incident, related: relatedIncidents(snapshot, incident).slice(0, 8) }));
  }
  return out;
}

/** Tags added, changed or removed between two runs. */
export function changedTags(previous: Map<string, string>, next: Map<string, string>): string[] {
  const changed = [...next].filter(([tag, value]) => previous.get(tag) !== value).map(([tag]) => tag);
  return [...changed, ...[...previous.keys()].filter((tag) => !next.has(tag))];
}

/**
 * For a run whose picture is degraded: the CVE tags whose KEV catalogue entry was added, changed or
 * removed since the stored map, and that map with only those KEV parts replaced, so the next healthy run
 * does not count them again.
 */
export function kevChanges(previous: Map<string, string>, kevCatalog: Vuln[]): { changed: string[]; next: Map<string, string> } {
  const entries = new Map(kevCatalog.map((vuln) => [cveTag(vuln.cve), digest(vuln)]));
  const next = new Map(previous);
  const changed: string[] = [];
  for (const [tag, value] of previous) {
    const [page, kev] = value.split(".");
    // Incident fingerprints have no KEV part.
    if (kev === undefined) continue;
    const now = entries.get(tag) ?? NONE;
    if (now === kev) continue;
    changed.push(tag);
    if (page === NONE && now === NONE) next.delete(tag);
    else next.set(tag, `${page}.${now}`);
  }
  for (const [tag, kev] of entries) {
    if (previous.has(tag)) continue;
    changed.push(tag);
    next.set(tag, `${NONE}.${kev}`);
  }
  return { changed, next };
}

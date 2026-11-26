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
    out.set(
      cveTag(cve),
      digest({
        vuln: listed.find((vuln) => vuln.cve === cve) ?? null,
        onMap: isInSnapshot(snapshot, cve),
        mentions: mentions.slice(0, 12),
        mentionCount: mentions.length,
        kev: kev?.get(cve) ?? null,
      }),
    );
  }
  for (const [cve, entry] of kev ?? []) {
    if (!out.has(cveTag(cve))) out.set(cveTag(cve), digest({ kev: entry }));
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

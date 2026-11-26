import "server-only";

import { getSnapshot, snapshotDegraded } from "@/lib/snapshot";
import { getCveRecord, getKevCatalog } from "@/lib/sources/vulns";
import type { Incident, Vuln } from "@/lib/types";

export async function findIncident(id: string): Promise<Incident | undefined> {
  const snapshot = await getSnapshot();
  return snapshot.incidents.find((incident) => incident.id === id);
}

export function isCveId(value: string): boolean {
  return /^CVE-\d{4}-\d{4,7}$/.test(value);
}

/** Everything we know about a CVE: snapshot lists, the full KEV catalogue, then the CVE record. */
export async function findVuln(cve: string): Promise<Vuln | null> {
  return (await findVulnChecked(cve)).vuln;
}

/**
 * findVuln, and whether every source it needed answered. Incomplete when the snapshot was degraded, the
 * KEV catalogue failed, or the CVE record was needed and its lookup failed: a page built from that is
 * kept briefly rather than until the record changes.
 */
export async function findVulnChecked(cve: string): Promise<{ vuln: Vuln | null; complete: boolean }> {
  const id = cve.toUpperCase();
  if (!isCveId(id)) return { vuln: null, complete: true };
  // In parallel: each is cached, and the record lookup is cheap next to waiting on the other two first.
  const [snapshot, catalogue, record] = await Promise.all([
    getSnapshot(),
    getKevCatalog().catch(() => null),
    getCveRecord(id).then(
      (value) => ({ ok: true, value }),
      () => ({ ok: false, value: null }),
    ),
  ]);
  const fromSnapshot = [...snapshot.trending, ...snapshot.fresh, ...snapshot.kev].find((vuln) => vuln.cve === id);
  const kev = catalogue?.find((vuln) => vuln.cve === id);
  const needsRecord = !(fromSnapshot?.description && fromSnapshot.cvss);
  const nvd = needsRecord ? record.value : null;
  const complete = !snapshotDegraded(snapshot) && catalogue !== null && (!needsRecord || record.ok);
  const base = fromSnapshot ?? kev ?? nvd;
  if (!base) return { vuln: null, complete };
  return {
    complete,
    vuln: {
      ...nvd,
      ...base,
      kev: Boolean(kev) || base.kev,
      kevAdded: kev?.kevAdded ?? base.kevAdded,
      kevDue: kev?.kevDue ?? base.kevDue,
      ransomware: kev?.ransomware ?? base.ransomware,
      vendor: base.vendor || kev?.vendor || nvd?.vendor || "",
      product: base.product || kev?.product || nvd?.product || "",
      description: [base.description, kev?.description, nvd?.description].filter(Boolean).sort((a, b) => b!.length - a!.length)[0] ?? "",
      cvss: base.cvss ?? nvd?.cvss,
      severity: base.severity ?? nvd?.severity,
      published: base.published ?? nvd?.published,
      references: [...new Set([...(base.references ?? []), ...(kev?.references ?? []), ...(nvd?.references ?? [])])].slice(0, 10),
    },
  };
}

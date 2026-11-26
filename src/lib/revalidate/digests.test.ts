import { describe, expect, it } from "vitest";

import { changedTags, pageDigests } from "@/lib/revalidate/digests";
import type { Incident, Snapshot, Vuln } from "@/lib/types";

// A CVE or incident page is expired by tag only when its fingerprint changes, so a field the pages
// render but the fingerprint misses leaves them stale, and a field that changes every run (such as
// generatedAt) would expire every page on every run.

function vuln(cve: string, extra: Partial<Vuln> = {}): Vuln {
  return { cve, vendor: "Acme", product: "Gateway", name: `${cve} flaw`, description: "A flaw.", kev: false, ransomware: false, references: [], ...extra };
}

function incident(id: string, extra: Partial<Incident> = {}): Incident {
  return {
    id,
    victim: id,
    type: "ransomware",
    status: "claimed",
    title: `${id} attacked`,
    summary: "",
    cves: [],
    country: "US",
    lat: 0,
    lon: 0,
    geoBasis: "country",
    date: "2026-11-20T00:00:00Z",
    updated: "2026-11-20T00:00:00Z",
    severity: 2,
    confidence: 0.8,
    sources: [{ title: "Report", url: "https://example.test/report" }],
    origin: "news",
    ...extra,
  };
}

function fixture(): { snapshot: Snapshot; kev: Vuln[] } {
  const snapshot = {
    generatedAt: "2026-11-26T10:00:00Z",
    incidents: [
      incident("victim-a", { actor: "Akira", cves: ["CVE-2026-0001"] }),
      incident("victim-b", { actor: "Akira" }),
      incident("victim-c", { actor: "Qilin" }),
    ],
    trending: [vuln("CVE-2026-0001")],
    fresh: [],
    kev: [],
    malware: [],
    outages: [],
    stats: {},
    feeds: {},
  } as unknown as Snapshot;
  return { snapshot, kev: [vuln("CVE-2026-0001", { kev: true, kevAdded: "2026-11-25", kevDue: "2026-12-16" }), vuln("CVE-2020-0002", { kev: true })] };
}

const cases: { name: string; change: (data: ReturnType<typeof fixture>) => void; tag: string; changes: boolean }[] = [
  { name: "the snapshot flags it as exploited", change: ({ snapshot }) => (snapshot.trending[0].kev = true), tag: "cve:CVE-2026-0001", changes: true },
  { name: "CISA marks ransomware use", change: ({ kev }) => (kev[0].ransomware = true), tag: "cve:CVE-2026-0001", changes: true },
  { name: "CISA moves the due date", change: ({ kev }) => (kev[0].kevDue = "2026-12-30"), tag: "cve:CVE-2026-0001", changes: true },
  { name: "a catalogue-only entry changes", change: ({ kev }) => (kev[1].ransomware = true), tag: "cve:CVE-2020-0002", changes: true },
  {
    name: "a new incident mentions it",
    change: ({ snapshot }) => (snapshot.incidents[2].cves = ["CVE-2026-0001"]),
    tag: "cve:CVE-2026-0001",
    changes: true,
  },
  {
    name: "a mentioning incident is confirmed",
    change: ({ snapshot }) => (snapshot.incidents[0].status = "confirmed"),
    tag: "cve:CVE-2026-0001",
    changes: true,
  },
  { name: "its status changes", change: ({ snapshot }) => (snapshot.incidents[0].status = "confirmed"), tag: "incident:victim-a", changes: true },
  { name: "a related incident changes", change: ({ snapshot }) => (snapshot.incidents[1].status = "confirmed"), tag: "incident:victim-a", changes: true },
  { name: "an unrelated incident changes", change: ({ snapshot }) => (snapshot.incidents[2].status = "confirmed"), tag: "cve:CVE-2026-0001", changes: false },
  { name: "an unrelated incident changes", change: ({ snapshot }) => (snapshot.incidents[2].status = "confirmed"), tag: "incident:victim-a", changes: false },
];

describe("page digests", () => {
  it.each(cases)("$tag when $name: changed=$changes", ({ change, tag, changes }) => {
    const before = fixture();
    const after = fixture();
    change(after);
    expect(changedTags(pageDigests(before.snapshot, before.kev), pageDigests(after.snapshot, after.kev)).includes(tag)).toBe(changes);
  });

  it("expires nothing when only the build time changes", () => {
    const before = fixture();
    const after = fixture();
    after.snapshot.generatedAt = "2026-11-26T10:10:00Z";
    expect(changedTags(pageDigests(before.snapshot, before.kev), pageDigests(after.snapshot, after.kev))).toEqual([]);
  });

  it("expires a page whose CVE leaves the picture", () => {
    const before = fixture();
    const after = fixture();
    after.snapshot.trending = [];
    after.snapshot.incidents[0].cves = [];
    after.kev.shift();
    expect(changedTags(pageDigests(before.snapshot, before.kev), pageDigests(after.snapshot, after.kev))).toContain("cve:CVE-2026-0001");
  });
});

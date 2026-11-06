import { describe, expect, it, vi } from "vitest";
import { reserveReviewedMembership, resolveReviewedAdvisories } from "@/lib/sources/advisories";
import type { Vuln } from "@/lib/types";
import registry from "@/data/reviewed-advisories.json";

vi.mock("server-only", () => ({}));
vi.mock("next/cache", () => ({ cacheLife: vi.fn(), cacheTag: vi.fn() }));
vi.mock("@/lib/pipeline", () => ({ buildIncidents: async () => [] }));
vi.mock("@/lib/sources/context", () => ({ getLatestBrief: async () => null, getOutages: async () => [] }));
vi.mock("@/lib/sources/incidents", () => ({ getNewsIncidents: async () => [], getRansomwareClaims: async () => [], getSecDisclosures: async () => [], getSweepIncidents: async () => [] }));
vi.mock("@/lib/sources/vulns", () => ({
  getKevCatalog: async () => [], getRecentCriticalCves: async () => [], getCriticalAdvisories: async () => [],
  getLatestCriticalCves: async () => Array.from({ length: 80 }, (_, i) => ({ ...record, cve: `CVE-2026-${10000 + i}`, severity: "CRITICAL", cvss: 9.8 })),
  getMalwarePackages: async () => [], getCveNewsMentions: async () => ({ [record.cve]: 2 }),
  getCveRecord: async (cve: string) => [record, ...paint].find((entry) => entry.cve === cve) ?? null, getEpss: async () => new Map(),
}));

const now = Date.parse("2026-11-06T16:00:00Z");
const published = "2026-11-05T15:46:26.488Z";
const source = "https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/";
const record: Vuln = { cve: "CVE-2026-123158", vendor: "OpenBSD", product: "OpenSSH", name: "OpenSSH", description: "Password authentication bypass", cvss: 8.1, severity: "HIGH", published, kev: false, ransomware: false, references: ["https://www.cve.org/CVERecord?id=CVE-2026-123158"] };
const paint: Vuln[] = [
  { ...record, cve: "CVE-2026-83844", vendor: "Microsoft", product: "Microsoft Paint", name: "Windows Paint Remote Code Execution Vulnerability", cvss: 8.1, published: "2026-10-13T18:59:53.598Z", references: ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-83844"] },
  { ...record, cve: "CVE-2026-70586", vendor: "Microsoft", product: "Windows 10 Version 1607", name: "Windows Paint Remote Code Execution Vulnerability", cvss: 8.8, published: "2026-09-08T17:12:23.405Z", references: ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-70586"] },
];

describe("reviewed advisory eligibility", () => {
  it("integrates into fresh and trending at overflow without changing critical stats or real news counts", async () => {
    vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      const { getSnapshot } = await import("@/lib/snapshot");
      const snapshot = await getSnapshot();
      expect(snapshot.fresh).toHaveLength(40);
      expect(snapshot.trending).toHaveLength(60);
      for (const feed of [snapshot.fresh, snapshot.trending]) {
        const matches = feed.filter((v) => v.cve === record.cve);
        expect(matches).toHaveLength(1);
        expect(matches[0]).toMatchObject({ severity: "HIGH", cvss: 8.1, published, kev: false, ransomware: false, newsCount: 2 });
        expect(matches[0].references).toContain(source);
        expect(matches[0].references).toContain(record.references[0]);
        for (const original of paint) {
          const matches = feed.filter((v) => v.cve === original.cve);
          expect(matches).toHaveLength(1);
          expect(matches[0]).toEqual(original);
          expect(matches[0].newsCount).toBeUndefined();
        }
      }
      expect(snapshot.stats.criticalCves72h).toBe(80);
      expect(snapshot.incidents.some((incident) => incident.cves.some((cve) => paint.some((v) => v.cve === cve)))).toBe(false);
    } finally { vi.restoreAllMocks(); }
  });
  it("features both older Paint records only during the explicit seven-day window", async () => {
    const lookup = async (cve: string) => paint.find((v) => v.cve === cve) ?? null;
    expect(await resolveReviewedAdvisories(Date.parse("2026-11-06T00:00:00Z"), lookup)).toEqual(paint);
    expect(await resolveReviewedAdvisories(Date.parse("2026-11-12T23:59:59.999Z"), lookup)).toEqual(paint);
    expect(await resolveReviewedAdvisories(Date.parse("2026-11-13T00:00:00Z"), lookup)).toEqual([]);
    expect(await resolveReviewedAdvisories(Date.parse("2026-11-05T23:59:59.999Z"), lookup)).toEqual([]);
  });

  it.each(["invalid", "2026-11-07T00:00:00Z", "2026-10-30T16:00:00Z", "2026-11-31T00:00:00Z", ""])("rejects malformed, future or expired feature window %s", async (featuredFrom) => {
    const lookup = vi.fn(async () => paint[0]);
    expect(await resolveReviewedAdvisories(now, lookup, [{ ...registry[1], featuredFrom }])).toEqual([]);
    expect(lookup).not.toHaveBeenCalled();
  });

  it.each(["invalid", "2026-11-07T00:00:00Z", "2026-02-30T00:00:00Z", undefined])("never bypasses source publication validation with a feature window: %s", async (date) => {
    expect(await resolveReviewedAdvisories(now, async () => ({ ...paint[0], published: date }))).toEqual([]);
    if (date !== undefined) {
      expect(await resolveReviewedAdvisories(now, async () => paint[0], [{ ...registry[1], published: date }])).toEqual([]);
    }
  });

  it("keeps reviewed lookups and reserved membership bounded to eight", async () => {
    const entries = Array.from({ length: 20 }, (_, i) => ({ ...registry[1], cve: `CVE-2026-${20000 + i}` }));
    const lookup = vi.fn(async (cve: string) => ({ ...paint[0], cve }));
    const reviewed = await resolveReviewedAdvisories(now, lookup, entries);
    expect(lookup).toHaveBeenCalledTimes(8);
    expect(reviewed).toHaveLength(8);
    const ranked = Array.from({ length: 80 }, (_, i) => ({ ...record, cve: `CVE-2026-${30000 + i}` }));
    expect(reserveReviewedMembership([...ranked, ...reviewed], reviewed, 40).filter((v) => reviewed.some((r) => r.cve === v.cve))).toHaveLength(8);
  });
  it("includes the registry High using real publication and evidence without inventing claims", async () => {
    const [result] = await resolveReviewedAdvisories(now, async () => record);
    expect(result).toEqual({ ...record, references: [source, ...record.references] });
    expect(result.newsCount).toBeUndefined();
    expect(result.kev).toBe(false);
    expect(result.ransomware).toBe(false);
    expect([result].filter((v) => v.severity === "CRITICAL")).toHaveLength(0);
  });

  it.each(["2026-10-30T16:00:00Z", "2026-11-07T00:00:00Z", "invalid", undefined])("excludes source publication %s", async (date) => {
    expect(await resolveReviewedAdvisories(now, async () => ({ ...record, published: date }))).toEqual([]);
  });

  it("rejects expired, future and malformed registry entries before lookup", async () => {
    const lookup = vi.fn(async () => record);
    const entries = [
      { cve: record.cve, published: "2026-10-30T16:00:00Z", source },
      { cve: record.cve, published: "2026-11-07T00:00:00Z", source },
      { cve: "bad", published, source },
      { cve: record.cve, published, source: "javascript:alert(1)" },
    ];
    expect(await resolveReviewedAdvisories(now, lookup, entries)).toEqual([]);
    expect(lookup).not.toHaveBeenCalled();
  });

  it("safely skips absent/rejected, failed and mismatched lookups", async () => {
    expect(await resolveReviewedAdvisories(now, async () => null)).toEqual([]);
    expect(await resolveReviewedAdvisories(now, async () => { throw new Error("unavailable"); })).toEqual([]);
    expect(await resolveReviewedAdvisories(now, async () => ({ ...record, cve: "CVE-2026-9999" }))).toEqual([]);
  });

  it.each([40, 60])("reserves membership under cap %s, deduping without losing evidence", async (cap) => {
    const reviewed = await resolveReviewedAdvisories(now, async () => record);
    const ranked = Array.from({ length: 80 }, (_, i) => ({ ...record, cve: `CVE-2026-${10000 + i}`, severity: "CRITICAL" as const }));
    const result = reserveReviewedMembership([...ranked, ...reviewed, ...reviewed], reviewed, cap);
    expect(result).toHaveLength(cap);
    expect(result.at(-1)).toEqual(reviewed[0]);
    expect(result.filter((v) => v.cve === record.cve)).toHaveLength(1);
    expect(ranked.filter((v) => v.severity === "CRITICAL")).toHaveLength(80);
  });
});

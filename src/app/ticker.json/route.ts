import type { TickerVuln } from "@/components/hud/cve-ticker";
import { getSnapshot } from "@/lib/snapshot";

/**
 * The new-CVE banner's data, for the site bar on every page outside the live map. Prerendered and
 * revalidated with the snapshot, so the pages themselves do not carry the snapshot and the banner is one
 * shared CDN entry.
 */
export async function GET() {
  const { fresh, generatedAt } = await getSnapshot();
  // Only what the ticker draws, a few kilobytes rather than full advisories.
  const items: TickerVuln[] = fresh.map(({ cve, vendor, product, cvss, kev, ransomware, kevAdded, published }) => ({
    cve,
    vendor,
    product,
    cvss,
    kev,
    ransomware,
    kevAdded,
    published,
  }));
  return Response.json({ generatedAt, items });
}

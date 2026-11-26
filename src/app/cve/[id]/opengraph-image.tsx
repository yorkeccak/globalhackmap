import { cacheLife, cacheTag } from "next/cache";

import { cveTag } from "@/lib/cache-tags";
import { loadCve } from "@/lib/cve-page";
import { cardBytes, pngResponse } from "@/lib/og/card";
import { cveCard, fallbackCard } from "@/lib/og/cards";
import { cveMentions } from "@/lib/og/select";
import { getSnapshot, snapshotDegraded } from "@/lib/snapshot";
import { cveParams } from "@/lib/static-params";
import { decodeParam } from "@/lib/utils";

export const alt = "Global Hack Map vulnerability card: whether it is exploited in the wild, the chance of exploitation and its severity";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export async function generateStaticParams() {
  return cveParams();
}

/** The card, kept until the CVE's data changes, like its page. */
async function render(cve: string): Promise<ArrayBuffer> {
  "use cache";
  cacheTag(cveTag(cve));
  const [{ vuln, kevKnown, complete }, snapshot] = await Promise.all([loadCve(cve), getSnapshot().catch(() => null)]);
  if (complete && snapshot && !snapshotDegraded(snapshot)) cacheLife("record");
  else cacheLife("minutes");
  if (!vuln) return cardBytes(fallbackCard(`${cve} not found`, "Check the ID, or search every exploited flaw on the live map."));
  return cardBytes(cveCard(vuln, snapshot ? cveMentions(snapshot, vuln.cve) : [], kevKnown));
}

export default async function Image({ params }: { params: Promise<{ id: string }> }) {
  return pngResponse(await render(decodeParam((await params).id).toUpperCase()));
}

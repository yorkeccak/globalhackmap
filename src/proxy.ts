import { NextResponse, type NextRequest } from "next/server";

import countries from "@/data/geo/countries.json";
import { clientIp, limitResponse, takeLimits } from "@/lib/http/rate-limit";
import { requestLimits } from "@/lib/http/request-limits";
import { isAuthorizedCron } from "@/lib/http/cron";

const CVE_ID = /^CVE-\d{4}-\d{4,7}$/i;

/** Renders the site's not-found page with a real 404, rather than a streamed page that has already sent 200. */
function notFound(request: NextRequest) {
  return NextResponse.rewrite(new URL("/_not-found", request.url), { status: 404 });
}

/** A permanent redirect to the canonical form, sent before any HTML so search engines see a 308. */
function canonical(request: NextRequest, segments: string[]) {
  const url = request.nextUrl.clone();
  url.pathname = `/${segments.map(encodeURIComponent).join("/")}`;
  return NextResponse.redirect(url, 308);
}

/**
 * Next decodes dynamic route params before any page code runs, and answers a malformed escape
 * ("/cve/%zz") with a bare 500. Reject those as the bad requests they are.
 *
 * Pages stream their shell before the lookup inside can call notFound(), so a bad id would otherwise
 * answer 200. IDs that cannot exist (not a CVE ID, not a country code) are turned away here instead.
 */
export async function proxy(request: NextRequest) {
  let path: string;
  try {
    path = decodeURIComponent(request.nextUrl.pathname);
  } catch {
    return new NextResponse("Bad request: the URL has a malformed escape sequence.", { status: 400 });
  }
  // Authenticated scheduled jobs must keep working during a limiter outage.
  const scheduled = path.startsWith("/api/cron/") && isAuthorizedCron(request);
  // Runbooks are the only page lookups with a per-visitor budget; CVE and country pages are cached.
  const runbook = /^\/fix\/[^/]+/.test(path);
  if ((path.startsWith("/api/") && !scheduled) || runbook) {
    const response = limitResponse(await takeLimits(requestLimits(path, request.method, clientIp(request))));
    if (response) return response;
  }
  const [, section, id, ...rest] = path.split("/");
  if (!id) return NextResponse.next();
  if (section === "cve" || section === "fix") {
    if (!CVE_ID.test(id)) return notFound(request);
    if (id !== id.toUpperCase()) return canonical(request, [section, id.toUpperCase(), ...rest]);
  }
  if (section === "country" && /^[a-z]{2}$/i.test(id)) {
    const iso = id.toUpperCase() === "UK" ? "GB" : id.toUpperCase();
    if (!(iso in countries)) return notFound(request);
    if (iso !== id) return canonical(request, [section, iso, ...rest]);
  }
  return NextResponse.next();
}

/**
 * Canonical CVE pages and OG images (with their RSC and segment-prefetch forms), incident pages and
 * the cached, parameterless GET APIs need nothing from the proxy, so it does not run for them.
 * Lowercase, malformed and escaped CVE IDs still match and get their 308, 404 or 400.
 */
export const config = {
  matcher: [
    "/cve/((?!CVE-\\d{4}-\\d{4,7}(?:/opengraph-image)?(?:\\.rsc|\\.segments/[^%]+\\.segment\\.rsc)?$).*)",
    "/country/:path*",
    "/fix/:path*",
    "/api/((?!logo$|snapshot$|patch$).*)",
  ],
};

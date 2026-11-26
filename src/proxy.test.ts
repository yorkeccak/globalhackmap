import { unstable_doesMiddlewareMatch } from "next/experimental/testing/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { config } from "./proxy";

const runs = (url: string) => unstable_doesMiddlewareMatch({ config, nextConfig: {}, url });

// Guards the proxy matcher: a pattern that lets a malformed CVE ID reach the page would stream a 200
// for an ID that cannot exist, and one that skips the paid APIs would drop their per-IP limits.
describe("proxy matcher", () => {
  it.each([
    "/cve/CVE-2024-1234567.rsc",
    "/cve/CVE-2021-44228/opengraph-image",
    "/cve/CVE-2021-44228.rsc",
    "/cve/CVE-2021-44228.segments/_tree.segment.rsc",
    "/incident/dygav-es-2026-11",
    "/incident/dygav-es-2026-11/opengraph-image",
    "/api/logo",
    "/api/snapshot",
    "/api/patch",
  ])("skips %s", (url) => expect(runs(url)).toBe(false));

  it.each([
    // Vercel ignores case when matching, so the HTML form runs the proxy to redirect lowercase IDs.
    "/cve/CVE-2021-44228",
    "/cve/cve-2021-44228",
    "/cve/cve-2021-44228.rsc",
    "/cve/CVE-1",
    "/cve/%zz",
    "/cve/CVE-2021-44228%zz",
    "/cve/CVE-2021-44228/extra",
    "/country/zz",
    "/country/us",
    "/fix/CVE-2021-44228",
    "/api/brief",
    "/api/mcp",
    "/api/check",
    "/api/research",
    "/api/explain/CVE-2021-44228",
    "/api/auth/token",
    "/api/cron/sweep",
    "/api/logo/extra",
  ])("runs on %s", (url) => expect(runs(url)).toBe(true));
});

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";

// Offline component/DOM regression. No app server, upstream calls or package downloads.
// AGENT_BROWSER_BIN=/path/to/installed/agent-browser node scripts/test-notable-advisory-browser.mjs
const require = createRequire(import.meta.url);
const exec = promisify(execFile);
const noop = () => null;
const shell = ({ children }) => h("div", null, children);
const link = ({ href, children, tabIndex, "aria-label": label }) => h("a", { href, tabIndex, "aria-label": label }, children);
const now = "2026-11-06T12:00:00Z";
const advisory = {
  cve: "CVE-2026-123158",
  vendor: "OpenBSD",
  product: "OpenSSH",
  name: "OpenSSH advisory",
  description: "Fixture advisory affecting OpenSSH on Alpine Linux.",
  severity: "HIGH",
  cvss: 8.1,
  kev: false,
  ransomware: false,
  published: now,
  references: [],
};
const paint = [
  { ...advisory, cve: "CVE-2026-83844", vendor: "Microsoft", product: "Paint", name: "Paint advisory", published: "2026-10-13T00:00:00Z", cvss: 8.1 },
  { ...advisory, cve: "CVE-2026-70586", vendor: "Microsoft", product: "Paint", name: "Paint advisory", published: "2026-09-08T00:00:00Z", cvss: 8.8 },
].map((entry) => ({ ...entry, description: "Fixture for a selected older Paint advisory." }));
const fresh = Array.from({ length: 28 }, (_, i) => ({
  ...advisory,
  cve: `CVE-2026-${200000 + i}`,
  name: "Fixture critical advisory",
  severity: "CRITICAL",
  cvss: 9.1,
})).concat(advisory, { ...advisory, cve: "CVE-2026-300000", severity: undefined, cvss: undefined }, ...paint);
// A fresh KEV entry absent from trending and the historical catalogue must also remain visible.
fresh[27] = { ...fresh[27], kev: true };
const trending = [
  ...fresh.slice(0, 2),
  ...paint,
  ...Array.from({ length: 28 }, (_, i) => ({
    ...advisory,
    cve: `CVE-2026-${400000 + i}`,
    kev: true,
  })),
];
const kev = [
  ...trending.filter((v) => v.kev),
  ...Array.from({ length: 30 }, (_, i) => ({
    ...advisory,
    cve: `CVE-2026-${500000 + i}`,
    kev: true,
    kevAdded: "2026-11-06",
  })),
];
const snapshot = { generatedAt: now, fresh, trending, kev };
const state = { tab: "exploited", window: "24h", statuses: new Set(["confirmed", "reported", "claimed"]) };

// Keep React's actual renderer; replace data/services and unrelated child components only.
const mocks = {
  "next/link": { default: link },
  "next/cache": { cacheLife: noop },
  "@number-flow/react": { default: ({ value }) => h("span", null, value) },
  "@phosphor-icons/react": { ArrowUpRight: noop, FilmSlate: noop, Newspaper: noop, SidebarSimple: noop },
  "@phosphor-icons/react/ssr": { ArrowRight: noop },
  "@/stores/situation": { WINDOW_MS: { "24h": 86400000 }, useSituation: (select) => select(state) },
  "@/stores/stack": { useStack: (select) => select({ items: [] }), stackMatch: () => false },
  "@/lib/perf/use-now": { useNow: (time) => time },
  "@/lib/countries": { countryName: (iso) => iso },
  "@/lib/snapshot": { getSnapshot: async () => snapshot },
  "@/components/auth/allowance-hint": { AllowanceHint: noop },
  "@/components/hud/ai-brief": { AnswerCard: noop },
  "@/components/hud/omnibox": { Omnibox: noop },
  "@/components/hud/patch-strip": { PatchStrip: noop },
  "@/components/hud/stack-picker": { StackPicker: noop },
  "@/components/kit/org-logo": { OrgLogo: noop },
  "@/components/kit/status-mark": { StatusMark: noop },
  "@/components/kit/segmented": {
    Segmented: ({ options }) =>
      h(
        "nav",
        null,
        options.map((o) => h("span", { key: o.value, "data-tab": o.value }, `${o.label} ${o.count ?? ""}`)),
      ),
  },
  "@/components/pages/breadcrumbs": { Breadcrumbs: noop },
  "@/components/pages/json-ld": { JsonLd: noop, breadcrumbList: noop },
  "@/components/pages/page-shell": { PageShell: shell },
  "@/components/pages/styles": { PRIMARY: "", SECONDARY: "" },
  "@/components/pages/tile": { Tile: shell, TileHead: shell, Eyebrow: ({ as = "span", children, ...props }) => h(as, props, children) },
};
const modules = new Map();
function load(relative) {
  const path = fileURLToPath(new URL(`../${relative}`, import.meta.url));
  if (modules.has(path)) return modules.get(path);
  const code = ts.transpileModule(readFileSync(path, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true, target: ts.ScriptTarget.ES2022 },
    fileName: path,
  }).outputText;
  const module = { exports: {} };
  const localRequire = (id) => {
    if (id in mocks) return { __esModule: true, ...mocks[id] };
    if (id.startsWith("@/")) return load(`src/${id.slice(2)}.ts`);
    return require(id);
  };
  new Function("require", "module", "exports", code)(localRequire, module, module.exports);
  modules.set(path, module.exports);
  return module.exports;
}

const { Story } = load("src/components/hud/story.tsx");
const { CveTicker } = load("src/components/hud/cve-ticker.tsx");
const { default: CveIndex, metadata } = load("src/app/cve/page.tsx");
const story = renderToStaticMarkup(
  h(Story, {
    ...snapshot,
    vulns: [...fresh, ...trending],
    incidents: [],
    allIncidents: [],
    incidentDays: [],
    malware: [],
    outages: [],
    incidentSummary: { statusCounts: { confirmed: 0, reported: 0, claimed: 0 }, organisations: 0, incidentCount: 0 },
  }),
);
const ticker = renderToStaticMarkup(h(CveTicker, { items: fresh, generatedAt: now }));
const index = renderToStaticMarkup(await CveIndex());
assert.match(story, /High<!-- --> 8\.1|High 8\.1/);
assert.match(story, /Severity unknown/);
assert.match(index, /Advisories to review/);
assert.match(metadata.description, /selected older vendor advisories/);
assert.doesNotMatch(`${metadata.title} ${metadata.description}`, /new CVEs|recent advisories/i);
assert.match(ticker, /CVE WATCH/);
console.log("PASS actual component rendering: High 8.1, unknown severity, watch labels and older-advisory copy");

const server = createServer((_, response) => {
  response.setHeader("Content-Type", "text/html; charset=utf-8");
  response.end(
    `<!doctype html><html lang="en"><title>Offline advisory regression</title><body><main id="story">${story}</main><div id="ticker">${ticker}</div><div id="index">${index}</div></body></html>`,
  );
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const bin = process.env.AGENT_BROWSER_BIN ?? "agent-browser";
let session;
async function browser(...args) {
  const { stdout } = await exec(bin, ["--session", session, "--json", ...args], { encoding: "utf8", timeout: 60000 });
  const response = JSON.parse(stdout);
  assert.equal(response.success, true, JSON.stringify(response));
  return response.data;
}
try {
  session = (await exec(bin, ["session", "id", "--scope", "worktree", "--prefix", "notable-advisory"], { encoding: "utf8" })).stdout.trim();
  await browser("open", `http://127.0.0.1:${server.address().port}`);
  const result = (
    await browser(
      "eval",
      `(() => {
    const rows = [...document.querySelectorAll('#story [role="tabpanel"] li')];
    const advisory = rows.filter(row => row.textContent.includes('CVE-2026-123158'));
    const tickerLists = [...document.querySelectorAll('#ticker ul')];
    const indexLink = document.querySelector('#index a[href="/cve/CVE-2026-123158"]');
    const paints = ['CVE-2026-83844', 'CVE-2026-70586'].map(id => {
      const homeRows = rows.filter(row => row.textContent.includes(id));
      const tickerLinks = [...tickerLists[0].querySelectorAll('a')].filter(a => a.getAttribute('href') === '/cve/' + id);
      const indexLinks = [...document.querySelectorAll('#index a')].filter(a => a.getAttribute('href') === '/cve/' + id);
      return {
        id, homeCount: homeRows.length, tickerCount: tickerLinks.length, indexCount: indexLinks.length,
        home: homeRows[0]?.textContent, ticker: tickerLinks[0]?.textContent, index: indexLinks[0]?.textContent,
        heading: homeRows[0]?.closest('section').getAttribute('aria-label'),
        statusColors: [...homeRows[0].querySelectorAll('[class]'), ...tickerLinks[0].querySelectorAll('[class]'), ...indexLinks[0].querySelectorAll('[class]')]
          .some(el => /(?:text|bg)-(?:confirmed|reported)/.test(el.className))
      };
    });
    return {
      paints,
      tickerLabel: document.querySelector('#ticker a').getAttribute('aria-label'),
      tickerListLabel: tickerLists[0].getAttribute('aria-label'),
      headings: [...document.querySelectorAll('#index h1, #index h2')].map(el => el.textContent),
      rowCount: rows.length, uniqueCount: new Set(rows.map(row => row.textContent.match(/CVE-\\d{4}-\\d+/)?.[0])).size,
      tab: document.querySelector('[data-tab="exploited"]').textContent,
      advisoryCount: advisory.length, advisoryText: advisory[0]?.textContent,
      freshKev: rows.find(row => row.textContent.includes('CVE-2026-200027'))?.textContent,
      tickerCounts: tickerLists.map(list => list.querySelectorAll('li').length),
      tickerAdvisory: tickerLists[0].querySelector('a[href="/cve/CVE-2026-123158"]')?.textContent,
      duplicateFocusable: [...tickerLists[1].querySelectorAll('a')].some(a => a.tabIndex !== -1),
      indexText: indexLink?.textContent, indexCount: document.querySelectorAll('#index #new').length
    };
  })()`,
    )
  ).result;
  assert.equal(result.rowCount, 85);
  assert.equal(result.uniqueCount, result.rowCount);
  assert.equal(result.tab, "CVEs 85");
  assert.equal(result.advisoryCount, 1);
  assert.match(result.freshKev, /Exploited/);
  assert.match(result.advisoryText, /High 8\.1/);
  assert.doesNotMatch(result.advisoryText, /Critical|Exploited|In the news|Ransomware/);
  assert.deepEqual(result.tickerCounts, [32, 32]);
  assert.match(result.tickerAdvisory, /8\.1.*OpenSSH.*CVE-2026-123158/);
  assert.equal(result.duplicateFocusable, false);
  assert.match(result.indexText, /High 8\.1/);
  assert.doesNotMatch(result.indexText, /Critical|Exploited|In the news/);
  assert.equal(result.indexCount, 1);
  assert.equal(result.tickerLabel, "CVE watch: advisories and exploited vulnerabilities");
  assert.equal(result.tickerListLabel, "Advisories to review and confirmed exploited CVEs");
  assert.doesNotMatch(result.headings.join(" "), /new CVEs|recent advisories/i);
  const { relativeTime } = load("src/lib/format.ts");
  for (const [i, entry] of paint.entries()) {
    const rendered = result.paints[i];
    const age = relativeTime(entry.published, Date.parse(now));
    assert.equal(rendered.id, entry.cve);
    assert.deepEqual([rendered.homeCount, rendered.tickerCount, rendered.indexCount], [1, 1, 1]);
    assert.equal(rendered.heading, "Advisories to review");
    assert.equal(rendered.statusColors, false);
    for (const text of [rendered.home, rendered.index]) {
      assert.ok(text.includes(`High ${entry.cvss.toFixed(1)}`));
      assert.ok(text.includes(`published ${age}`), `${entry.cve} must keep its original publication age`);
    }
    assert.ok(rendered.ticker.includes(age.replace(" ago", "")));
    assert.doesNotMatch([rendered.home, rendered.ticker, rendered.index].join(" "), /new|recent|critical|exploited|in the news|ransomware/i);
    console.log(`PASS ${entry.cve}: once per list, High ${entry.cvss.toFixed(1)}, original publication ${entry.published.slice(0, 10)} (${age}), neutral status`);
  }
  console.log("PASS browser DOM: 32 fresh + 28 unique trending + 25 unique KEV = 85 rows and matching tab count");
  console.log("PASS advisory at position 29 appears once, High 8.1, in home list, ticker and index");
  console.log("PASS ticker retains all 32 entries; duplicate track is removed from tab order");
} finally {
  if (session) await browser("close");
  await new Promise((resolve) => server.close(resolve));
}

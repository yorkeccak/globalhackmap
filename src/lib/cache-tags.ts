/**
 * Cache tags for pages about one record. /api/cron/revalidate expires a tag when what its page renders
 * changes (src/lib/revalidate/digests.ts), so these pages can keep a long timed lifetime.
 */
export const cveTag = (id: string) => `cve:${id}`;
export const incidentTag = (id: string) => `incident:${id}`;
/** Every page that shows a per-CVE EPSS score: expired when FIRST publishes a new model date. */
export const EPSS_TAG = "epss";

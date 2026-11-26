import "server-only";

/**
 * Upstash REST credentials, or null when none are set. Vercel's integration can expose the KV_* names;
 * credential pairs are kept together, and the read-only token never stands in for the write token.
 */
export function upstashCredentials(): { url: string; token: string } | null {
  const explicit = Boolean(process.env.UPSTASH_REDIS_REST_URL || process.env.UPSTASH_REDIS_REST_TOKEN);
  const url = explicit ? process.env.UPSTASH_REDIS_REST_URL : process.env.KV_REST_API_URL;
  const token = explicit ? process.env.UPSTASH_REDIS_REST_TOKEN : process.env.KV_REST_API_TOKEN;
  return url && token ? { url, token } : null;
}

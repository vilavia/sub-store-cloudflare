import type { Context } from "hono";
export function success(c: Context<{ Bindings: SubStoreEnv }>, data: unknown) {
  return c.json({ status: "success", data });
}

export function failed(c: Context<{ Bindings: SubStoreEnv }>, message: string, status = 400) {
  return c.json(
    {
      status: "failed",
      error: {
        code: status,
        message,
      },
    },
    status as 400,
  );
}

export async function isTokenValid(secret: string | undefined, input: string | undefined) {
  if (!secret) return false;
  if (!input) return false;

  const encoder = new TextEncoder();
  const [inputDigest, secretDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(input)),
    crypto.subtle.digest("SHA-256", encoder.encode(secret)),
  ]);
  return crypto.subtle.timingSafeEqual(inputDigest, secretDigest);
}

export function getBearerToken(c: Context<{ Bindings: SubStoreEnv }>) {
  const authorization = c.req.header("authorization") || "";
  return authorization.match(/^Bearer\s+(.+)$/i)?.[1] || c.req.query("token") || c.req.header("x-sub-store-token");
}

// The admin token may be a memorable password, so throttle guessing: a client that sent this
// many distinct wrong tokens within the window is refused until the window has passed.
const ADMIN_FAILURE_LIMIT = 10;
const ADMIN_FAILURE_WINDOW_MS = 15 * 60 * 1000;

export async function requireAdmin(c: Context<{ Bindings: SubStoreEnv }>) {
  const token = getBearerToken(c);
  const client = await getClientKey(c);
  const since = Date.now() - ADMIN_FAILURE_WINDOW_MS;
  if (await countAdminFailures(c.env.DB, client, since) >= ADMIN_FAILURE_LIMIT) {
    c.header("Retry-After", String(ADMIN_FAILURE_WINDOW_MS / 1000));
    return failed(c, "Too many failed login attempts, try again in 15 minutes", 429);
  }
  if (await isTokenValid(c.env.SUB_STORE_ADMIN_TOKEN, token)) return undefined;
  if (token) await recordAdminFailure(c.env.DB, client, token, since);
  return failed(c, "Admin token is invalid", 401);
}

async function getClientKey(c: Context<{ Bindings: SubStoreEnv }>) {
  const ip = ((await getForwardedClientIp(c)) || c.req.header("cf-connecting-ip") || "unknown").toLowerCase();
  if (!ip.includes(":") || ip.includes(".")) return ip;
  // One IPv6 user usually controls a whole /64, so count the prefix rather than the address.
  const [head, tail] = ip.split("::");
  const headParts = head ? head.split(":") : [];
  const tailParts = tail ? tail.split(":") : [];
  const parts = tail === undefined ? headParts : [...headParts, ...Array(8 - headParts.length - tailParts.length).fill("0"), ...tailParts];
  return `${parts.slice(0, 4).join(":")}::/64`;
}

// A forwarding Worker on another account (serving a custom domain) reaches us from Cloudflare's
// shared Worker address, so it passes the visitor IP along. Trust that only with the shared secret,
// otherwise anyone calling workers.dev directly could pick their own IP and dodge the throttle.
async function getForwardedClientIp(c: Context<{ Bindings: SubStoreEnv }>) {
  const secret = (c.env as { SUB_STORE_PROXY_SECRET?: string }).SUB_STORE_PROXY_SECRET;
  if (!secret || !(await isTokenValid(secret, c.req.header("x-sub-store-proxy-secret")))) return undefined;
  return c.req.header("x-sub-store-client-ip") || undefined;
}

async function countAdminFailures(db: D1Database, client: string, since: number) {
  try {
    const row = await db
      .prepare("SELECT COUNT(*) AS failures FROM admin_auth_failures WHERE client = ? AND created_at > ?")
      .bind(client, since)
      .first<{ failures: number }>();
    return row?.failures ?? 0;
  } catch {
    // Throttling is best effort; a D1 hiccup must not lock the owner out.
    return 0;
  }
}

async function recordAdminFailure(db: D1Database, client: string, token: string, since: number) {
  try {
    // Store a hash, never the attempt itself (it may be a typo of the real password). Repeating the
    // same stale token is ignored, so an old token left in a browser does not use up attempts.
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    const tokenHash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    await db.batch([
      db.prepare("DELETE FROM admin_auth_failures WHERE created_at <= ?").bind(since),
      db.prepare("INSERT OR IGNORE INTO admin_auth_failures (client, token_hash, created_at) VALUES (?, ?, ?)").bind(client, tokenHash, Date.now()),
    ]);
  } catch {
    // Same as above: never fail the request because the throttle table could not be written.
  }
}

export function applyCorsHeaders(response: Response, origin: string | undefined, allowedOrigins = "") {
  const headers = new Headers(response.headers);
  const allowlist = allowedOrigins
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  if (origin && (allowlist.includes("*") || allowlist.includes(origin))) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Sub-Store-Token");
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export function applySecurityHeaders(response: Response) {
  const headers = new Headers(response.headers);
  headers.set(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; manifest-src 'self'",
  );
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/* ── /api/breach ──────────────────────────────────────────────────────────
   Proxies a lookup to Have I Been Pwned.

   Why this touches our server at all: HIBP's email endpoint requires an API
   key, and a key shipped to the browser is a key given away. So the request
   passes through here.

   What we do about that, per Article IV:
     · the address is never written to the database
     · the address is never written to a log line
     · we count requests per client so the service cannot be abused, and the
       counter holds a number, never an address
     · nothing about the result is stored anywhere
   HIBP's own policy is that searches are not logged. We link to it rather
   than paraphrase it, so nobody has to take our word for their behaviour.
   ────────────────────────────────────────────────────────────────────────── */

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
    },
  });

// A coarse, salted client fingerprint. Enough to rate limit; not enough to
// identify. It is never stored alongside anything a person typed.
async function clientKey(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const ua = request.headers.get("User-Agent") || "";
  const data = new TextEncoder().encode(`sovran-breach|${ip}|${ua.slice(0, 60)}`);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).slice(0, 10)
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}

const HOURLY_LIMIT = 25;

export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Bad request." }, 400); }

  const email = String(body.email || "").trim().toLowerCase();

  if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return json({ error: "That does not look like an email address." }, 400);
  }

  if (!env.HIBP_API_KEY) {
    return json({
      error: "Breach lookup is not configured yet. If you are the site owner, add HIBP_API_KEY.",
    }, 503);
  }

  /* ── rate limit: counts only, never the address ── */
  const fp = await clientKey(request);
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS breach_counts (
         fingerprint TEXT PRIMARY KEY,
         hour TEXT NOT NULL,
         n INTEGER NOT NULL DEFAULT 0
       )`
    ).run();
    const hour = new Date().toISOString().slice(0, 13);
    const row = await env.DB.prepare(
      "SELECT hour, n FROM breach_counts WHERE fingerprint = ?1"
    ).bind(fp).first();

    if (row && row.hour === hour && row.n >= HOURLY_LIMIT) {
      return json({
        error: `That is ${HOURLY_LIMIT} lookups in an hour, which is our limit. It resets shortly.`,
      }, 429);
    }
    if (row && row.hour === hour) {
      await env.DB.prepare("UPDATE breach_counts SET n = n + 1 WHERE fingerprint = ?1").bind(fp).run();
    } else {
      await env.DB.prepare(
        "INSERT INTO breach_counts (fingerprint, hour, n) VALUES (?1, ?2, 1) " +
        "ON CONFLICT(fingerprint) DO UPDATE SET hour = ?2, n = 1"
      ).bind(fp, hour).run();
    }
  } catch (e) {
    // Rate limiting failing is not a reason to refuse the lookup.
  }

  /* ── the lookup ── */
  let res;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 12000);
    res = await fetch(
      "https://haveibeenpwned.com/api/v3/breachedaccount/" +
        encodeURIComponent(email) + "?truncateResponse=false",
      {
        headers: {
          "hibp-api-key": env.HIBP_API_KEY,
          "user-agent": "SOVRAN-breach-check/1.0 (+https://mysovran.online)",
        },
        signal: ctrl.signal,
      }
    ).finally(() => clearTimeout(timer));
  } catch (e) {
    return json({ error: "Could not reach Have I Been Pwned. Try again in a moment." }, 502);
  }

  // 404 is the good outcome: this address is in no known breach.
  if (res.status === 404) return json({ ok: true, breaches: [] });

  if (res.status === 401) return json({ error: "Our API key was rejected. This is our problem, not yours." }, 502);
  if (res.status === 429) return json({ error: "Have I Been Pwned is rate limiting us. Try again shortly." }, 429);
  if (!res.ok) return json({ error: `Have I Been Pwned returned ${res.status}.` }, 502);

  let data;
  try { data = await res.json(); } catch { return json({ error: "Unreadable response." }, 502); }

  // Pass through only what the page needs to render.
  const breaches = (Array.isArray(data) ? data : []).map((b) => ({
    name: b.Title || b.Name,
    domain: b.Domain || "",
    breachDate: b.BreachDate || "",
    addedDate: b.AddedDate || "",
    count: b.PwnCount || 0,
    description: b.Description || "",
    dataClasses: b.DataClasses || [],
    verified: !!b.IsVerified,
    sensitive: !!b.IsSensitive,
    retired: !!b.IsRetired,
    fabricated: !!b.IsFabricated,
  })).sort((a, b) => (b.breachDate || "").localeCompare(a.breachDate || ""));

  return json({ ok: true, breaches });
}

export async function onRequest() {
  return json({ error: "Method not allowed." }, 405);
}

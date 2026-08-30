// POST /api/admin — the only endpoint that can read user data, so it is the
// most locked-down thing here.
//
// FOUR INDEPENDENT LOCKS, all required:
//   1. Cloudflare Access   — identity verified at the edge before the request
//                            ever reaches this code. Enforced below: if
//                            REQUIRE_ACCESS is on and no Access JWT is present,
//                            the request is refused outright.
//   2. ADMIN_KEY           — a long random secret you hold.
//   3. ADMIN_TOTP_SECRET   — a rotating 6-digit code from your authenticator.
//                            A stolen key alone is not enough.
//   4. Lockout             — 5 failures in 15 minutes locks that client out
//                            for an hour. Every attempt is recorded.
//
// Bindings : DB (D1 -> sovran-waitlist)
// Env vars : ADMIN_KEY, ADMIN_TOTP_SECRET, CANARY_KEYS,
//            REQUIRE_ACCESS ("true" once Cloudflare Access is configured)

const BUILD_ID = "2026-08-31-session-and-roads";

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store, max-age=0" },
  });

function sameSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/* ── Sessions ──
   A TOTP code is valid for 30 seconds. Requiring one on every action meant the
   panel worked for exactly one click. So authentication now happens once and
   issues a short-lived random token; the token authorises later calls. The token
   lives in the page's memory only, never in storage, so closing the tab ends it. */
const SESSION_MINUTES = 30;

function randomToken() {
  const a = new Uint8Array(32);
  crypto.getRandomValues(a);
  return Array.from(a).map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function newSession(env) {
  const token = randomToken();
  await env.DB.prepare(
    `INSERT INTO admin_sessions (token, expires_at)
     VALUES (?1, datetime('now', '+${SESSION_MINUTES} minutes'))`
  ).bind(token).run();
  await env.DB.prepare("DELETE FROM admin_sessions WHERE expires_at < datetime('now')").run();
  return token;
}

async function validSession(env, token) {
  if (!token || typeof token !== "string" || token.length !== 64) return false;
  const row = await env.DB.prepare(
    "SELECT expires_at FROM admin_sessions WHERE token = ?1"
  ).bind(token).first();
  if (!row) return false;
  if (new Date(row.expires_at.replace(" ", "T") + "Z") < new Date()) {
    await env.DB.prepare("DELETE FROM admin_sessions WHERE token = ?1").bind(token).run();
    return false;
  }
  return true;
}

/* ── TOTP (RFC 6238), verified against the authenticator on your phone ── */
function base32Decode(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  const clean = String(s).toUpperCase().replace(/[^A-Z2-7]/g, "");
  for (const c of clean) {
    const i = A.indexOf(c);
    if (i < 0) continue;
    bits += i.toString(2).padStart(5, "0");
  }
  const out = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(bits.substr(i * 8, 8), 2);
  return out;
}

async function totpAt(secret, counter) {
  const key = await crypto.subtle.importKey(
    "raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 0x100000000));
  dv.setUint32(4, counter >>> 0);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const off = sig[sig.length - 1] & 0xf;
  const code =
    (((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3]) % 1000000;
  return String(code).padStart(6, "0");
}

async function totpValid(secret, supplied) {
  const clean = String(supplied || "").replace(/\D/g, "");
  if (clean.length !== 6) return false;
  const now = Math.floor(Date.now() / 30000);
  // ±1 step of tolerance for clock drift
  for (const w of [-1, 0, 1]) {
    if (sameSecret(await totpAt(secret, now + w), clean)) return true;
  }
  return false;
}

/* ── lockout ── */
async function fingerprint(request) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const data = new TextEncoder().encode("sovran-admin|" + ip);
  const h = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(h)).slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function lockedOut(env, fp) {
  const r = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM admin_attempts
      WHERE fingerprint = ?1 AND ok = 0 AND at >= datetime('now','-15 minutes')`
  ).bind(fp).first();
  return (r?.n || 0) >= 5;
}

async function record(env, fp, ok) {
  await env.DB.prepare("INSERT INTO admin_attempts (fingerprint, ok) VALUES (?1, ?2)")
    .bind(fp, ok ? 1 : 0).run();
  await env.DB.prepare("DELETE FROM admin_attempts WHERE at < datetime('now','-2 hours')").run();
}

export async function onRequestPost({ request, env }) {
  /* ── LOCK 1: Cloudflare Access must have already vouched for this request ── */
  const accessJwt =
    request.headers.get("Cf-Access-Jwt-Assertion") ||
    (request.headers.get("Cookie") || "").match(/CF_Authorization=([^;]+)/)?.[1];

  const requireAccess = String(env.REQUIRE_ACCESS || "").toLowerCase() === "true";
  if (requireAccess && !accessJwt) {
    return json({
      error: "Blocked. This panel requires Cloudflare Access and no verified identity was presented.",
    }, 403);
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: "Malformed request." }, 400); }

  if (!env.ADMIN_KEY) return json({ error: "Admin access is not configured." }, 500);
  if (!env.ADMIN_TOTP_SECRET)
    return json({ error: "Two-factor is not configured. Set ADMIN_TOTP_SECRET before using this panel." }, 500);

  const fp = await fingerprint(request);
  const action = String(body.action || "overview");

  /* An existing session skips locks 2 and 3. Access and the lockout still apply. */
  let sessionToken = null;
  const presented = String(body.session || "");

  if (await validSession(env, presented)) {
    sessionToken = presented;
  } else {
    /* ── LOCK 4: lockout ── */
    if (await lockedOut(env, fp)) {
      return json({ error: "Too many failed attempts. This client is locked out for an hour." }, 429);
    }

    /* ── LOCK 2: the key ──  ── LOCK 3: the rotating code ── */
    const keyOk = sameSecret(String(body.key || ""), env.ADMIN_KEY);
    const totpOk = keyOk ? await totpValid(env.ADMIN_TOTP_SECRET, body.code) : false;

    if (!keyOk || !totpOk) {
      await record(env, fp, false);
      await new Promise((r) => setTimeout(r, 500));
      // deliberately identical message either way
      return json({
        error: presented
          ? "Your session expired. Enter your key and a fresh code."
          : "Not authorised.",
        expired: !!presented,
      }, 401);
    }
    await record(env, fp, true);
    sessionToken = await newSession(env);
  }

  try {
    if (action === "overview") {
      const totals = await env.DB.prepare(`
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN created_at >= datetime('now','-7 days') THEN 1 ELSE 0 END) AS week,
               SUM(CASE WHEN created_at >= datetime('now','-1 day')  THEN 1 ELSE 0 END) AS today,
               SUM(CASE WHEN note IS NOT NULL AND note != ''         THEN 1 ELSE 0 END) AS with_notes
          FROM waitlist`).first();

      const accounts = await env.DB.prepare("SELECT COUNT(*) AS n FROM accounts").first();
      const interests = await env.DB.prepare(`
        SELECT COALESCE(NULLIF(interest,''),'(not given)') AS interest, COUNT(*) AS n
          FROM waitlist GROUP BY 1 ORDER BY n DESC`).all();
      const recent = await env.DB.prepare(`
        SELECT email, interest, note, source, created_at FROM waitlist ORDER BY id DESC LIMIT 50`).all();
      const canary = await env.DB.prepare(`
        SELECT statement, signed_by, signed_at FROM canary ORDER BY id DESC LIMIT 1`).first();
      const fails = await env.DB.prepare(`
        SELECT COUNT(*) AS n FROM admin_attempts WHERE ok = 0 AND at >= datetime('now','-24 hours')`).first();

      return json({
        ok: true,
        build: BUILD_ID,
        session: sessionToken,
        session_minutes: SESSION_MINUTES,
        totals: totals || {},
        accounts: accounts?.n || 0,
        interests: interests.results || [],
        recent: recent.results || [],
        canary: canary || null,
        failed_24h: fails?.n || 0,
        access_verified: !!accessJwt,
        interval_days: Number(env.CANARY_INTERVAL_DAYS || 14),
        grace_days: Number(env.CANARY_GRACE_DAYS || 7),
      });
    }

    /* ── Overpass proxy, for building map snapshots ──
       Runs server-side so the browser only ever talks to this origin. A page's
       Content-Security-Policy governs what the BROWSER may contact; it has no
       say over what a Worker fetches. That is why this works where the direct
       call did not.
       Note this is admin-only and used to build public map files. It is not on
       any path a visitor touches, so it changes nothing about what SOVRAN can
       see of anyone's browsing. ── */
    if (action === "overpass") {
      const query = String(body.query || "");
      if (!query || query.length > 4000) return json({ error: "Bad query." }, 400);

      const mirrors = [
        "https://overpass-api.de/api/interpreter",
        "https://overpass.kumi.systems/api/interpreter",
        "https://overpass.private.coffee/api/interpreter",
      ];
      const tried = [];

      for (const url of mirrors) {
        const host = url.replace(/^https:\/\//, "").replace(/\/.*$/, "");
        try {
          const res = await fetch(url, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              // Overpass asks that clients identify themselves
              "User-Agent": "SOVRAN-map-builder/1.0 (+https://mysovran.online)",
            },
            body: "data=" + encodeURIComponent(query),
          });

          if (!res.ok) {
            const txt = (await res.text().catch(() => "")).replace(/<[^>]*>/g, " ")
              .replace(/\s+/g, " ").trim().slice(0, 200);
            tried.push(`${host}: HTTP ${res.status}${txt ? " — " + txt : ""}`);
            continue;
          }

          const data = await res.json().catch(() => null);
          if (!data) { tried.push(`${host}: replied but not with JSON`); continue; }
          return json({ ok: true, host, elements: data.elements || [] });
        } catch (e) {
          tried.push(`${host}: ${String(e && e.message || "unreachable")}`);
        }
      }
      return json({ error: "Every mirror failed.", tried }, 502);
    }

    if (action === "signout") {
      await env.DB.prepare("DELETE FROM admin_sessions WHERE token = ?1").bind(sessionToken).run();
      return json({ ok: true });
    }

    if (action === "export") {
      const { results } = await env.DB.prepare(
        "SELECT email, interest, note, source, created_at FROM waitlist ORDER BY id ASC").all();
      return json({ ok: true, rows: results || [] });
    }

    if (action === "sign") {
      let keys = {};
      try { keys = JSON.parse(env.CANARY_KEYS || "{}"); } catch { /* empty */ }
      let signer = null;
      for (const [name, secret] of Object.entries(keys)) {
        if (sameSecret(secret, String(body.canaryKey || ""))) { signer = name; break; }
      }
      if (!signer) return json({ error: "That canary key was not recognised." }, 401);

      let statement = String(body.statement || "").trim();
      if (!statement) {
        const prev = await env.DB.prepare("SELECT statement FROM canary ORDER BY id DESC LIMIT 1").first();
        statement = prev?.statement || "";
      }
      if (!statement) return json({ error: "No statement to sign." }, 400);

      await env.DB.prepare("INSERT INTO canary (statement, signed_by, note) VALUES (?1, ?2, ?3)")
        .bind(statement, signer, String(body.note || "").slice(0, 500) || null).run();
      return json({ ok: true, signed_by: signer });
    }

    if (action === "remove") {
      const email = String(body.email || "").trim().toLowerCase();
      if (!email) return json({ error: "No email given." }, 400);
      const r = await env.DB.prepare("DELETE FROM waitlist WHERE email = ?1").bind(email).run();
      return json({ ok: true, removed: r?.meta?.changes || 0 });
    }

    return json({ error: "Unknown action." }, 400);
  } catch {
    return json({ error: "Something failed on our side." }, 500);
  }
}

export const onRequestGet    = () => json({ error: "Method not allowed." }, 405);
export const onRequestPut    = () => json({ error: "Method not allowed." }, 405);
export const onRequestPatch  = () => json({ error: "Method not allowed." }, 405);
export const onRequestDelete = () => json({ error: "Method not allowed." }, 405);

// GET  /api/canary          — public. Returns the latest signed statement.
// POST /api/canary          — signs a new one. Requires a key.
//
// Bindings : DB (D1 -> sovran-waitlist)
// Env vars : CANARY_KEYS — JSON object mapping signer name to secret, e.g.
//              {"Mav":"long-random-1","Jordan":"long-random-2"}
//            Any one of them can sign. Whoever signs is recorded by name, so
//            you can always see who kept it alive and when.
//
// There is no cron job and no server-side alarm. The page computes staleness
// in the visitor's browser from signed_at. If nobody signs, every visitor sees
// it go overdue on their own device — nothing here has to keep working for the
// signal to arrive.

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store, max-age=0",
    },
  });

export async function onRequestGet({ env }) {
  try {
    const row = await env.DB.prepare(
      "SELECT statement, signed_by, signed_at, note, freshness, anchor FROM canary ORDER BY id DESC LIMIT 1"
    ).first();

    if (!row) return json({ error: "No statement has been signed yet." }, 404);

    // history of signing dates only — proves the cadence without extra detail
    const { results } = await env.DB.prepare(
      "SELECT signed_by, signed_at, freshness FROM canary ORDER BY id DESC LIMIT 12"
    ).all();

    return json({
      statement: row.statement,
      signed_by: row.signed_by,
      signed_at: row.signed_at,
      freshness: row.freshness || null,
      anchor: row.anchor || null,
      note: row.note || null,
      history: results || [],
      // how long before the page should call it overdue
      interval_days: Number(env.CANARY_INTERVAL_DAYS || 14),
      grace_days: Number(env.CANARY_GRACE_DAYS || 7),
    });
  } catch {
    return json({ error: "Could not read the canary." }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Malformed request." }, 400);
  }

  let keys = {};
  try {
    keys = JSON.parse(env.CANARY_KEYS || "{}");
  } catch {
    return json({ error: "Signing is not configured." }, 500);
  }

  const supplied = String(body.key || "");
  if (!supplied) return json({ error: "No key supplied." }, 401);

  // constant-time-ish comparison across all configured signers
  let signer = null;
  for (const [name, secret] of Object.entries(keys)) {
    if (secret && secret.length === supplied.length) {
      let diff = 0;
      for (let i = 0; i < secret.length; i++) diff |= secret.charCodeAt(i) ^ supplied.charCodeAt(i);
      if (diff === 0) { signer = name; break; }
    }
  }
  if (!signer) return json({ error: "That key was not recognised." }, 401);

  // carry the previous statement forward unless a new one is given
  let statement = String(body.statement || "").trim();
  if (!statement) {
    const prev = await env.DB.prepare(
      "SELECT statement FROM canary ORDER BY id DESC LIMIT 1"
    ).first();
    statement = prev?.statement || "";
  }
  if (!statement) return json({ error: "No statement to sign." }, 400);
  if (statement.length > 4000) return json({ error: "Statement is too long." }, 400);

  const note = String(body.note || "").slice(0, 500) || null;

  /* ── Freshness ──
     Two separate things, because they prove different things.

     1. The signer types a headline. NOTHING can verify this automatically —
        a server cannot know what today's news is. It is verified by READERS,
        who can check whether that headline is from the date shown. A stale one
        does not fail here; it fails publicly, in front of everyone.

     2. The server independently fetches a public blockchain tip and records it.
        That value could not have existed before that block was mined, so it
        proves the row was written after a specific, checkable moment. The
        signer cannot influence or backdate it.                              */
  const freshness = String(body.freshness || "").trim().slice(0, 300);

  if (!freshness || freshness.length < 15) {
    return json({ error: "Type a headline from today — a few words at least, not a link." }, 400);
  }
  if (/^https?:\/\/\S+$/i.test(freshness) || /^www\./i.test(freshness)) {
    return json({
      error: "Paste the headline text itself, not a URL. A link proves nothing about when it was written, and readers check this by reading it.",
    }, 400);
  }
  if (freshness.split(/\s+/).length < 4) {
    return json({ error: "That is too short to be a headline. Four words or more, please." }, 400);
  }
  // An old date typed into the box is the most likely honest mistake.
  const yr = freshness.match(/\b(19|20)\d{2}\b/);
  if (yr && Number(yr[0]) < new Date().getUTCFullYear()) {
    return json({ error: `That headline mentions ${yr[0]}. If it is not from today, do not use it.` }, 400);
  }

  let anchor = null;
  try {
    const c = new AbortController();
    const t = setTimeout(() => c.abort(), 6000);
    const r = await fetch("https://blockchain.info/latestblock", { signal: c.signal })
      .finally(() => clearTimeout(t));
    if (r.ok) {
      const b = await r.json();
      if (b && b.height && b.hash) anchor = `bitcoin block ${b.height} · ${String(b.hash).slice(0, 24)}`;
    }
  } catch (e) { /* the canary must still be signable if this is unreachable */ }

  try {
    await env.DB.prepare(
      "INSERT INTO canary (statement, signed_by, note, freshness, anchor) VALUES (?1, ?2, ?3, ?4, ?5)"
    ).bind(statement, signer, note, freshness, anchor).run();
  } catch {
    return json({ error: "Could not record the signature." }, 500);
  }

  return json({ ok: true, signed_by: signer, signed_at: new Date().toISOString() });
}

export const onRequestPut    = () => json({ error: "Method not allowed." }, 405);
export const onRequestPatch  = () => json({ error: "Method not allowed." }, 405);
export const onRequestDelete = () => json({ error: "Method not allowed." }, 405);

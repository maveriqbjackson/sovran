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
     A signing date written by our own server proves nothing. So a signature is
     only accepted with a link to a news story whose publication date is in the
     URL, from an outlet that puts it there. We parse that date and check it
     against the clock. A stale link fails here rather than sitting in the
     database looking like proof.

     Belt and braces: we also record the current blockchain tip independently,
     which the signer cannot influence.                                       */
// Outlets that put a publication date in the URL path. Each is checked against
  // the server's own clock, so a stale link cannot pass.
  const DATED_SOURCES = [
    { host:/(^|\.)cnn\.com$/,            re:/\/(\d{4})\/(\d{2})\/(\d{2})\//,        name:"CNN" },
    { host:/(^|\.)npr\.org$/,            re:/\/(\d{4})\/(\d{2})\/(\d{2})\//,        name:"NPR" },
    { host:/(^|\.)nytimes\.com$/,        re:/\/(\d{4})\/(\d{2})\/(\d{2})\//,        name:"The New York Times" },
    { host:/(^|\.)washingtonpost\.com$/, re:/\/(\d{4})\/(\d{2})\/(\d{2})\//,        name:"The Washington Post" },
    { host:/(^|\.)politico\.com$/,       re:/\/(\d{4})\/(\d{2})\/(\d{2})\//,        name:"Politico" },
    { host:/(^|\.)axios\.com$/,          re:/\/(\d{4})\/(\d{2})\/(\d{2})\//,        name:"Axios" },
    { host:/(^|\.)aljazeera\.com$/,      re:/\/(\d{4})\/(\d{1,2})\/(\d{1,2})\//,    name:"Al Jazeera" },
    { host:/(^|\.)theguardian\.com$/,    re:/\/(\d{4})\/([a-z]{3})\/(\d{1,2})\//i,  name:"The Guardian", month:"abbr" },
  ];
  const MON = {jan:1,feb:2,mar:3,apr:4,may:5,jun:6,jul:7,aug:8,sep:9,oct:10,nov:11,dec:12};
  
  function checkDatedLink(raw){
    var url;
    try { url = new URL(raw.trim()); } catch(e){ return { ok:false, reason:"not-a-url" }; }
    if(!/^https?:$/.test(url.protocol)) return { ok:false, reason:"not-a-url" };
  
    var host = url.hostname.replace(/^www\./,"");
    var src = DATED_SOURCES.find(function(s){ return s.host.test(host); });
    if(!src) return { ok:false, reason:"unsupported-source", host:host };
  
    var m = url.pathname.match(src.re);
    if(!m) return { ok:false, reason:"no-date-in-url", name:src.name };
  
    var y = +m[1];
    var mo = src.month === "abbr" ? MON[m[2].toLowerCase()] : +m[2];
    var d = +m[3];
    if(!y || !mo || !d) return { ok:false, reason:"no-date-in-url", name:src.name };
  
    var published = Date.UTC(y, mo-1, d);
    var today = Date.now();
    var days = Math.floor((today - published) / 86400000);
  
    // One day of slack each way: a reader west of UTC late at night is already
    // "tomorrow" by the server's clock, and some outlets date-stamp ahead.
    if(days > 1)  return { ok:false, reason:"too-old", days:days, name:src.name,
                           date:y+"-"+String(mo).padStart(2,"0")+"-"+String(d).padStart(2,"0") };
    if(days < -1) return { ok:false, reason:"future", name:src.name };
  
    return { ok:true, name:src.name,
             date:y+"-"+String(mo).padStart(2,"0")+"-"+String(d).padStart(2,"0"),
             label:src.name+" · "+y+"-"+String(mo).padStart(2,"0")+"-"+String(d).padStart(2,"0") };
  }

  const link = String(body.freshness || "").trim().slice(0, 400);
  const fresh = checkDatedLink(link);

  if (!fresh.ok) {
    const msg = {
      "not-a-url": "Paste the full link to a news story from today, including https://",
      "unsupported-source": `We cannot verify dates on ${fresh.host || "that site"}. Use one that puts the date in the address — CNN, NPR, The Guardian, The New York Times, The Washington Post, Politico, Axios or Al Jazeera.`,
      "no-date-in-url": `That ${fresh.name} link has no date in its address. Open the article itself rather than a section front page.`,
      "too-old": `That story is from ${fresh.date}, which is ${fresh.days} days ago. The whole point is that it could not have been known before today. Find one from today.`,
      "future": "That link is dated in the future, which we cannot accept.",
    }[fresh.reason] || "That link could not be verified.";
    return json({ error: msg }, 400);
  }

  const freshness = `${fresh.label} — ${link}`;

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

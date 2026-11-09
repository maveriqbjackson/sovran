// GET /api/stats — numbers for Ash HQ (aetherandash.digital/hq). Never personal data, only counts.
// Locked: the caller must send header X-Team-Key = TEAM_SYNC_KEY (the same secret on both sites).
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });

export async function onRequestGet({ request, env }) {
  const key = request.headers.get('x-team-key') || '';
  if (!env.TEAM_SYNC_KEY || key.length < 24 || key !== env.TEAM_SYNC_KEY) return json({ error: 'Not allowed.' }, 403);
  const one = async (sql) => { try { return await env.DB.prepare(sql).first(); } catch { return null; } };
  const w = await one(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN created_at >= datetime('now','-7 days') THEN 1 ELSE 0 END) AS week,
      SUM(CASE WHEN created_at >= datetime('now','-1 day') THEN 1 ELSE 0 END) AS today FROM waitlist`);
  const a = await one('SELECT COUNT(*) AS n FROM accounts');
  const c = await one('SELECT signed_by, signed_at FROM canary ORDER BY id DESC LIMIT 1');
  return json({
    waitlist: { total: (w && w.total) || 0, week: (w && w.week) || 0, today: (w && w.today) || 0 },
    accounts: (a && a.n) || 0,
    canary: c ? { signed_at: c.signed_at } : null,
  });
}

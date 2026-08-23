// POST /api/waitlist
// Bindings required: DB (D1 -> vord-waitlist)
// Env vars required:  RESEND_API_KEY, NOTIFY_TO, NOTIFY_FROM

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

const esc = (s = "") =>
  String(s).replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Malformed request." }, 400);
  }

  // Honeypot — bots fill hidden fields, humans don't.
  if (body.company) return json({ ok: true });

  const email = String(body.email || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 254) {
    return json({ error: "That email address doesn't look complete." }, 400);
  }

  const interest = String(body.interest || "").slice(0, 120);
  const note = String(body.note || "").slice(0, 2000);
  const source = String(body.source || "vord-landing").slice(0, 60);
  const ua = String(request.headers.get("user-agent") || "").slice(0, 300);

  // 1) Store the signup.
  try {
    await env.DB.prepare(
      `INSERT INTO waitlist (email, interest, note, source, user_agent)
       VALUES (?1, ?2, ?3, ?4, ?5)
       ON CONFLICT(email) DO UPDATE SET
         interest = COALESCE(NULLIF(excluded.interest,''), waitlist.interest),
         note     = COALESCE(NULLIF(excluded.note,''),     waitlist.note)`
    ).bind(email, interest, note, source, ua).run();
  } catch (err) {
    return json({ error: "Couldn't save that. Try again in a moment." }, 500);
  }

  // 2) Notify. A failed email must never fail the signup.
  if (env.RESEND_API_KEY && env.NOTIFY_TO && env.NOTIFY_FROM) {
    try {
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: env.NOTIFY_FROM,
          to: [env.NOTIFY_TO],
          reply_to: email,
          subject: `SOVRAN waitlist — ${email}`,
          html: `
            <div style="font-family:system-ui,-apple-system,sans-serif;font-size:15px;line-height:1.6;color:#111">
              <h2 style="margin:0 0 16px;font-size:18px">New SOVRAN waitlist signup</h2>
              <p style="margin:0 0 6px"><strong>Email:</strong> ${esc(email)}</p>
              <p style="margin:0 0 6px"><strong>Interest:</strong> ${esc(interest) || "—"}</p>
              <p style="margin:0 0 6px"><strong>Source:</strong> ${esc(source)}</p>
              ${note ? `<p style="margin:16px 0 4px"><strong>Note:</strong></p>
              <blockquote style="margin:0;padding:12px 16px;background:#f6f6f4;border-left:3px solid #F5C36B;white-space:pre-wrap">${esc(note)}</blockquote>` : ""}
            </div>`,
        }),
      });
    } catch {
      // swallow — the row is already saved
    }
  }

  return json({ ok: true });
}

// Everything that is not a POST. Kept as explicit method handlers so the
// POST route above is never shadowed by a catch-all returning undefined.
export const onRequestGet    = () => json({ error: "Method not allowed." }, 405);
export const onRequestPut    = () => json({ error: "Method not allowed." }, 405);
export const onRequestPatch  = () => json({ error: "Method not allowed." }, 405);
export const onRequestDelete = () => json({ error: "Method not allowed." }, 405);

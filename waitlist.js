// POST /api/waitlist
//
// Bindings required : DB (D1 -> sovran-waitlist)
// Env vars required : RESEND_API_KEY, NOTIFY_TO, NOTIFY_FROM
// Env vars optional : SITE_URL  (defaults to the request's own origin)
//
// Behaviour:
//   • writes the signup to D1 first — a failed email never loses a signup
//   • sends the subscriber a confirmation, and Mav a notification
//   • detects repeat signups and does not re-send the confirmation
//   • issues a one-click unsubscribe token (see ./unsubscribe.js)

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

const esc = (s = "") =>
  String(s).replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c]));

/* ─────────────────────────────  confirmation email  ───────────────────────── */

function welcomeEmail(unsubUrl, siteUrl) {
  // Email clients are a hostile rendering environment: tables for layout,
  // inline styles only, no web fonts, no flexbox, no grid.
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Your place is held — SOVRAN</title>
</head>
<body style="margin:0;padding:0;background:#04060F;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">You're on the SOVRAN waitlist. Here's what happens next, and what you can already do today.</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#04060F" style="background:#04060F;">
<tr><td align="center" style="padding:34px 16px;">

  <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;">

    <!-- bifröst seam -->
    <tr><td style="height:4px;line-height:4px;font-size:0;background:#4FC3D9;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
        <td width="33%" bgcolor="#7B5CD6" style="height:4px;line-height:4px;font-size:0;">&nbsp;</td>
        <td width="34%" bgcolor="#4FC3D9" style="height:4px;line-height:4px;font-size:0;">&nbsp;</td>
        <td width="33%" bgcolor="#D9AE5F" style="height:4px;line-height:4px;font-size:0;">&nbsp;</td>
      </tr></table>
    </td></tr>

    <tr><td bgcolor="#0B1122" style="background:#0B1122;padding:38px 34px 34px;font-family:Helvetica,Arial,sans-serif;">

      <p style="margin:0 0 30px;font-size:15px;font-weight:bold;letter-spacing:3px;color:#EDE7DA;">
        S O V R A N
      </p>

      <h1 style="margin:0 0 20px;font-size:30px;line-height:1.15;font-weight:bold;color:#F2D9A0;letter-spacing:-0.5px;">
        Your place is held.
      </h1>

      <p style="margin:0 0 18px;font-size:16px;line-height:1.62;color:#B8BECD;">
        Thank you for signing up. You'll hear from us when there's something real to
        show you &mdash; not before. We'd rather send you four good emails a year than
        forty forgettable ones.
      </p>

      <p style="margin:0 0 26px;font-size:16px;line-height:1.62;color:#B8BECD;">
        In the meantime, one part of SOVRAN is already built and free to use.
      </p>

      <!-- the audit CTA -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
             style="background:#111A31;border:1px solid rgba(217,174,95,0.25);border-radius:14px;">
        <tr><td style="padding:24px;font-family:Helvetica,Arial,sans-serif;">
          <p style="margin:0 0 9px;font-size:11px;font-weight:bold;letter-spacing:2px;color:#D9AE5F;text-transform:uppercase;">
            Free forever &middot; Live now
          </p>
          <p style="margin:0 0 12px;font-size:19px;line-height:1.3;font-weight:bold;color:#EDE7DA;">
            Read back everything you've already published
          </p>
          <p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#9098AE;">
            Every platform is legally required to hand you a full archive of your own
            data. Download yours, drop it into The Audit, and see every coordinate,
            schedule pattern, and identifier you've been broadcasting without meaning to.
            It's read entirely inside your browser &mdash; turn off your wifi first and it
            still works.
          </p>
          <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
            <td bgcolor="#D9AE5F" style="border-radius:9px;">
              <a href="${siteUrl}/audit"
                 style="display:inline-block;padding:14px 26px;font-family:Helvetica,Arial,sans-serif;font-size:13px;font-weight:bold;letter-spacing:1.5px;text-transform:uppercase;color:#1E1403;text-decoration:none;">
                Run The Audit
              </a>
            </td>
          </tr></table>
        </td></tr>
      </table>

      <!-- charter reminder -->
      <p style="margin:30px 0 12px;font-size:11px;font-weight:bold;letter-spacing:2px;color:#D9AE5F;text-transform:uppercase;">
        What we hold on you
      </p>
      <p style="margin:0 0 8px;font-size:15px;line-height:1.6;color:#B8BECD;">
        Your email address. That's the entire list.
      </p>
      <p style="margin:0 0 30px;font-size:15px;line-height:1.6;color:#B8BECD;">
        No tracking pixel in this email, so we can't tell whether you opened it. No
        analytics on the site. No profile building quietly in the background. When we
        say a promise can be broken but an architecture has to be rebuilt, this is what
        we mean &mdash; there is nothing here to break.
      </p>

      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
        <tr><td style="border-top:1px solid rgba(232,224,206,0.12);padding-top:24px;font-family:Helvetica,Arial,sans-serif;">
          <p style="margin:0 0 6px;font-size:13px;line-height:1.6;color:#8A92AB;">
            Questions, criticism, or something we've got wrong &mdash; reply to this email.
            It reaches a person.
          </p>
          <p style="margin:0;font-size:13px;line-height:1.6;color:#8A92AB;">
            &mdash; Mav, <a href="https://aetherandash.digital" style="color:#D9AE5F;text-decoration:none;">Aether &amp; Ash</a>
          </p>
        </td></tr>
      </table>

    </td></tr>

    <tr><td style="padding:22px 34px 0;font-family:Helvetica,Arial,sans-serif;text-align:center;">
      <p style="margin:0 0 8px;font-size:12px;line-height:1.6;color:#5D6580;">
        You're receiving this because you joined the SOVRAN waitlist at
        <a href="${siteUrl}" style="color:#8A92AB;text-decoration:none;">mysovran.online</a>.
      </p>
      <p style="margin:0 0 8px;font-size:12px;line-height:1.6;color:#5D6580;">
        <a href="${unsubUrl}" style="color:#8A92AB;text-decoration:underline;">Remove me completely</a>
        &mdash; one click, no questions, no confirmation step.
      </p>
      <p style="margin:0;font-size:12px;line-height:1.6;color:#5D6580;">
        &copy; 2026 Aether &amp; Ash &middot; Colorado
      </p>
    </td></tr>

  </table>
</td></tr>
</table>
</body></html>`;
}

function welcomeText(unsubUrl, siteUrl) {
  return `SOVRAN

YOUR PLACE IS HELD.

Thank you for signing up. You'll hear from us when there's something real to
show you - not before. We'd rather send you four good emails a year than forty
forgettable ones.

In the meantime, one part of SOVRAN is already built and free to use.

--------------------------------------------------------------------
FREE FOREVER - LIVE NOW
Read back everything you've already published

Every platform is legally required to hand you a full archive of your own
data. Download yours, drop it into The Audit, and see every coordinate,
schedule pattern, and identifier you've been broadcasting without meaning
to. It's read entirely inside your browser - turn off your wifi first and
it still works.

Run The Audit: ${siteUrl}/audit
--------------------------------------------------------------------

WHAT WE HOLD ON YOU

Your email address. That's the entire list.

No tracking pixel in this email, so we can't tell whether you opened it. No
analytics on the site. No profile building quietly in the background. When we
say a promise can be broken but an architecture has to be rebuilt, this is
what we mean - there is nothing here to break.

Questions, criticism, or something we've got wrong - reply to this email.
It reaches a person.

- Mav, Aether & Ash


You're receiving this because you joined the SOVRAN waitlist at ${siteUrl}
Remove me completely (one click, no questions): ${unsubUrl}
(c) 2026 Aether & Ash - Colorado`;
}

/* ────────────────────────────────  handler  ──────────────────────────────── */

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
  const source = String(body.source || "sovran-landing").slice(0, 60);
  const ua = String(request.headers.get("user-agent") || "").slice(0, 300);

  const siteUrl = (env.SITE_URL || new URL(request.url).origin).replace(/\/+$/, "");

  /* 1 — store first. A failed email must never cost us a signup. */
  let isNew = false;
  let token;
  try {
    const existing = await env.DB.prepare(
      "SELECT id, token FROM waitlist WHERE email = ?1"
    ).bind(email).first();

    if (existing) {
      token = existing.token;
      if (!token) {
        token = crypto.randomUUID();
        await env.DB.prepare("UPDATE waitlist SET token = ?1 WHERE id = ?2")
          .bind(token, existing.id).run();
      }
      // let a returning person update what they told us
      if (interest || note) {
        await env.DB.prepare(
          `UPDATE waitlist
              SET interest = COALESCE(NULLIF(?1,''), interest),
                  note     = COALESCE(NULLIF(?2,''), note)
            WHERE id = ?3`
        ).bind(interest, note, existing.id).run();
      }
    } else {
      isNew = true;
      token = crypto.randomUUID();
      await env.DB.prepare(
        `INSERT INTO waitlist (email, interest, note, source, user_agent, token)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
      ).bind(email, interest, note, source, ua, token).run();
    }
  } catch (err) {
    return json({ error: "Couldn't save that. Try again in a moment." }, 500);
  }

  /* 2 — email. Never blocks or fails the signup. */
  const canSend = env.RESEND_API_KEY && env.NOTIFY_FROM;
  if (canSend) {
    const unsubUrl = `${siteUrl}/api/unsubscribe?t=${encodeURIComponent(token)}`;
    const from = /</.test(env.NOTIFY_FROM) ? env.NOTIFY_FROM : `SOVRAN <${env.NOTIFY_FROM}>`;

    const send = (payload) =>
      fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      }).catch(() => {});

    const jobs = [];

    // confirmation to the subscriber — only on a genuinely new signup
    if (isNew) {
      jobs.push(send({
        from,
        to: [email],
        reply_to: env.NOTIFY_TO || undefined,
        subject: "Your place is held — SOVRAN",
        html: welcomeEmail(unsubUrl, siteUrl),
        text: welcomeText(unsubUrl, siteUrl),
        headers: {
          "List-Unsubscribe": `<${unsubUrl}>`,
          "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        },
      }));
    }

    // notification to Mav
    if (env.NOTIFY_TO) {
      jobs.push(send({
        from,
        to: [env.NOTIFY_TO],
        reply_to: email,
        subject: `${isNew ? "SOVRAN waitlist" : "SOVRAN re-signup"} — ${email}`,
        html: `<div style="font-family:system-ui,-apple-system,sans-serif;font-size:15px;line-height:1.6;color:#111">
            <h2 style="margin:0 0 16px;font-size:18px">${isNew ? "New SOVRAN waitlist signup" : "Existing signup updated their details"}</h2>
            <p style="margin:0 0 6px"><strong>Email:</strong> ${esc(email)}</p>
            <p style="margin:0 0 6px"><strong>Interest:</strong> ${esc(interest) || "—"}</p>
            <p style="margin:0 0 6px"><strong>Source:</strong> ${esc(source)}</p>
            ${note ? `<p style="margin:16px 0 4px"><strong>Note:</strong></p>
            <blockquote style="margin:0;padding:12px 16px;background:#f6f6f4;border-left:3px solid #D9AE5F;white-space:pre-wrap">${esc(note)}</blockquote>` : ""}
          </div>`,
      }));
    }

    await Promise.allSettled(jobs);
  }

  return json({ ok: true, returning: !isNew });
}

// Everything that is not a POST. Explicit handlers so the POST route above is
// never shadowed by a catch-all returning undefined.
export const onRequestGet    = () => json({ error: "Method not allowed." }, 405);
export const onRequestPut    = () => json({ error: "Method not allowed." }, 405);
export const onRequestPatch  = () => json({ error: "Method not allowed." }, 405);
export const onRequestDelete = () => json({ error: "Method not allowed." }, 405);

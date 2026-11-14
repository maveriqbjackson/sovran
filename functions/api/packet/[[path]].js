// /api/packet/* — SOVRAN packet signing.
//
// The person signing only ever talks to mysovran.online. This passes each request along to Ash HQ
// (aetherandash.digital/api/sovsign/…), where the packet and the signing record live, and sends the
// two emails from SOVRAN's own address: the private link, and the signed copy afterwards.
//
//   GET  /api/packet/<token>          what's being signed and the link's state
//   GET  /api/packet/<token>/file     the packet PDF (the signed copy once signed)
//   POST /api/packet/<token>/sign     { name, consent, constitution, agreement }
//   POST /api/packet/<token>/notify   Ash HQ calls this once, right after Mav taps "Send to sign"
//
// Env: RESEND_API_KEY, NOTIFY_FROM (SOVRAN's sender), NOTIFY_TO (Mav). Optional HQ_ORIGIN.
// Nothing is stored here, and no IP address, device or location is recorded anywhere.

const SITE = "https://mysovran.online";
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store", "x-robots-tag": "noindex" } });
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export async function onRequest({ request, env, params }) {
  const [token, action = ""] = [].concat(params.path || []);
  if (!/^[a-f0-9]{64}$/.test(token || "")) return json({ error: "This link isn't valid. Ask SOVRAN to send a new one." }, 404);
  const hq = (env.HQ_ORIGIN || "https://aetherandash.digital") + "/api/sovsign/" + token + (action ? "/" + action : "");
  const up = (method, body) => fetch(hq, { method, headers: body ? { "content-type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });

  try {
    if (action === "file" && request.method === "GET") {
      const r = await up("GET");
      const h = new Headers({ "content-type": r.headers.get("content-type") || "application/pdf", "cache-control": "private, no-store", "x-robots-tag": "noindex",
        "content-disposition": 'inline; filename="SOVRAN packet.pdf"' });
      return new Response(r.body, { status: r.status, headers: h });
    }
    if (!action && request.method === "GET") { const r = await up("GET"); return json(await r.json().catch(() => ({ error: "Try again." })), r.status); }

    if (action === "notify" && request.method === "POST") {
      const r = await up("POST"); const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.email) return json({ error: j.error || "Couldn't read the link." }, r.ok ? 400 : r.status);
      const ok = await send(env, { to: [j.email], subject: `Your SOVRAN packet to read and sign`, html: linkEmail(j, token), text: linkText(j, token) });
      return ok ? json({ ok: true }) : json({ error: "SOVRAN's email isn't set up (RESEND_API_KEY / NOTIFY_FROM)." }, 502);
    }

    if (action === "sign" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const r = await up("POST", { name: body.name, consent: body.consent === true, constitution: body.constitution === true, agreement: body.agreement === true });
      const j = await r.json().catch(() => ({ error: "Something went wrong. Nothing was signed; try again." }));
      if (!r.ok) return json({ error: j.error }, r.status);
      // The signed copy, to them and to Mav. Then Ash HQ wipes their email.
      const attachments = j.pdf ? [{ filename: j.filename || "SOVRAN signed packet.pdf", content: j.pdf }] : undefined;
      const sentThem = j.email ? await send(env, { to: [j.email], subject: "Your signed SOVRAN packet", html: copyEmail(j, false), text: copyText(j), attachments }) : false;
      if (env.NOTIFY_TO) await send(env, { to: [env.NOTIFY_TO], subject: `[SOVRAN] ${j.first_name} signed the ${j.role} packet`, html: copyEmail(j, true), text: copyText(j), attachments });
      await fetch((env.HQ_ORIGIN || "https://aetherandash.digital") + "/api/sovsign/" + token + "/copied", { method: "POST" }).catch(() => {});
      return json({ ok: true, state: "signed", first_name: j.first_name, role: j.role, signed_at: j.signed_at, signed_name: j.signed_name, emailed: sentThem });
    }
    return json({ error: "Not allowed." }, 405);
  } catch (e) {
    return json({ error: "We couldn't reach the signing service. Nothing was signed; try again in a minute." }, 502);
  }
}

async function send(env, { to, subject, html, text, attachments }) {
  if (!env.RESEND_API_KEY || !env.NOTIFY_FROM) return false;
  const from = /</.test(env.NOTIFY_FROM) ? env.NOTIFY_FROM : `SOVRAN <${env.NOTIFY_FROM}>`;
  const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from, to, reply_to: env.NOTIFY_TO || undefined, subject, html, text, attachments }) }).catch(() => null);
  return !!(r && r.ok);
}

const fmt = (iso) => new Date(iso).toLocaleString("en-US", { timeZone: "America/Denver", dateStyle: "long", timeStyle: "short" }) + " Mountain";
function shell(pre, body) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"></head>
<body style="margin:0;padding:0;background:#04060F;"><div style="display:none;max-height:0;overflow:hidden;opacity:0;">${esc(pre)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#04060F" style="background:#04060F;"><tr><td align="center" style="padding:34px 16px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;">
<tr><td style="height:4px;line-height:4px;font-size:0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
<td width="33%" bgcolor="#7B5CD6" style="height:4px;line-height:4px;font-size:0;">&nbsp;</td><td width="34%" bgcolor="#4FC3D9" style="height:4px;line-height:4px;font-size:0;">&nbsp;</td><td width="33%" bgcolor="#D9AE5F" style="height:4px;line-height:4px;font-size:0;">&nbsp;</td></tr></table></td></tr>
<tr><td bgcolor="#0B1122" style="background:#0B1122;padding:38px 34px 34px;font-family:Helvetica,Arial,sans-serif;">
<p style="margin:0 0 30px;font-size:15px;font-weight:bold;letter-spacing:3px;color:#EDE7DA;">S O V R A N</p>${body}</td></tr>
<tr><td style="padding:18px 34px;font-family:Helvetica,Arial,sans-serif;font-size:12px;line-height:1.6;color:#74809B;">SOVRAN · mysovran.online · We never sell, share or track. This email is about your role with SOVRAN only.</td></tr>
</table></td></tr></table></body></html>`;
}
const P = (s) => `<p style="margin:0 0 16px;font-size:16px;line-height:1.62;color:#B8BECD;">${s}</p>`;
function linkEmail(j, token) {
  const url = `${SITE}/packet?t=${token}`;
  return shell(`Your packet for ${j.role} is ready to read and sign.`, `
<h1 style="margin:0 0 20px;font-size:30px;line-height:1.15;font-weight:bold;color:#F2D9A0;">Hi ${esc(j.first_name)}, your packet is ready.</h1>
${P(`This is your SOVRAN packet for <b style="color:#EDE7DA">${esc(j.role)}</b>: who we are, our Constitution, your role, the People-First Confidentiality Agreement, and your first 30 days.`)}
${P(`Read it at your own pace. When you're ready, you can sign it online in about a minute.`)}
<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:8px 0 24px;"><tr><td bgcolor="#F2D9A0" style="border-radius:10px;">
<a href="${url}" style="display:inline-block;padding:15px 26px;font-family:Helvetica,Arial,sans-serif;font-size:16px;font-weight:bold;color:#0B1122;text-decoration:none;">Read and sign your packet</a></td></tr></table>
${P(`The link is private to you and works until <b style="color:#EDE7DA">${esc(fmt(j.expires_at))}</b>. Please don't forward it.`)}
${P(`Tax and work-eligibility forms aren't part of this. We'll do those on paper, in person.`)}
${P(`Questions? Just reply to this email.`)}`);
}
const linkText = (j, token) => `Hi ${j.first_name},\n\nYour SOVRAN packet for ${j.role} is ready to read and sign:\n${SITE}/packet?t=${token}\n\nThe link is private to you and works until ${fmt(j.expires_at)}. Tax and work-eligibility forms aren't part of this; we'll do those on paper, in person.\n\nQuestions? Just reply.\n\nSOVRAN`;
function copyEmail(j, forMav) {
  return shell(forMav ? `${j.first_name} signed the ${j.role} packet.` : "Your signed SOVRAN packet is attached.", `
<h1 style="margin:0 0 20px;font-size:28px;line-height:1.15;font-weight:bold;color:#F2D9A0;">${forMav ? esc(j.first_name) + " signed." : "Signed. Thank you, " + esc(j.first_name) + "."}</h1>
${P(`${forMav ? esc(j.first_name) + " signed" : "You signed"} the SOVRAN packet for <b style="color:#EDE7DA">${esc(j.role)}</b> on ${esc(fmt(j.signed_at))}, as <b style="color:#EDE7DA">${esc(j.signed_name)}</b>.`)}
${P(`The signed copy is attached: the full packet with a signature page at the end. ${forMav ? "It's also saved in Ash HQ → SOVRAN → Documents." : "Keep it somewhere safe."}`)}
${P(`Fingerprint of the exact packet signed (SHA-256): <span style="font-family:Menlo,monospace;font-size:12px;color:#A2AEC6;word-break:break-all;">${esc(j.fingerprint || "")}</span>`)}`);
}
const copyText = (j) => `${j.first_name} signed the SOVRAN packet for ${j.role} on ${fmt(j.signed_at)}, as ${j.signed_name}. The signed copy is attached.\n\nFingerprint (SHA-256): ${j.fingerprint || ""}\n\nSOVRAN`;

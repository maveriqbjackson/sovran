// GET  /api/unsubscribe?t=TOKEN   — clicked from an email footer
// POST /api/unsubscribe?t=TOKEN   — RFC 8058 one-click, sent by Gmail/Yahoo
//
// Deletes the row outright. No soft-delete, no suppression list, no
// "are you sure" step. The landing page says "leave in one click, forever" —
// this is what makes that true rather than aspirational.

const page = (title, heading, body, ok = true) => new Response(
`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>${title} — SOVRAN</title>
<style>
@font-face{font-family:'Archivo';font-style:normal;font-weight:100 900;font-stretch:62% 125%;font-display:swap;
  src:url(/fonts/archivo-var.woff2) format('woff2-variations'),url(/fonts/archivo-var.woff2) format('woff2')}
@font-face{font-family:'IBM Plex Sans';font-style:normal;font-weight:100 700;font-display:swap;
  src:url(/fonts/plex-sans-var.woff2) format('woff2-variations'),url(/fonts/plex-sans-var.woff2) format('woff2')}
@font-face{font-family:'IBM Plex Mono';font-style:normal;font-weight:500;font-display:swap;
  src:url(/fonts/plex-mono-500.woff2) format('woff2')}
*{box-sizing:border-box;margin:0;padding:0}
body{background:#04060F;color:#EDE7DA;min-height:100vh;padding:40px 24px;
  font-family:'IBM Plex Sans',system-ui,-apple-system,sans-serif;font-size:17px;line-height:1.6;
  -webkit-font-smoothing:antialiased;display:flex;align-items:center;justify-content:center}
body::after{content:'';position:fixed;inset:0;pointer-events:none;
  background:radial-gradient(60ch 44ch at 80% 4%,rgba(123,92,214,.10),transparent 66%),
             radial-gradient(140ch 100ch at 50% 45%,transparent 40%,rgba(0,0,0,.55) 100%)}
main{position:relative;z-index:1;max-width:520px;width:100%}
.mark{font-family:'Archivo',sans-serif;font-weight:900;font-size:1.05rem;letter-spacing:.17em;
  text-transform:uppercase;color:#EDE7DA;text-decoration:none;display:inline-flex;align-items:center;
  gap:10px;margin-bottom:40px}
.code{font-family:'IBM Plex Mono',monospace;font-size:.67rem;font-weight:500;letter-spacing:.26em;
  text-transform:uppercase;color:${ok ? "#D9AE5F" : "#5BB8D4"};display:block;margin-bottom:18px}
h1{font-family:'Archivo',sans-serif;font-weight:900;font-variation-settings:'wdth' 118;
  text-transform:uppercase;font-size:clamp(1.8rem,7vw,2.8rem);letter-spacing:-.012em;line-height:1.08}
h1 .gilt{background:linear-gradient(160deg,#F2D9A0 8%,#D9AE5F 46%,#8F6B27 96%);
  -webkit-background-clip:text;background-clip:text;color:transparent}
p{color:#8A92AB;margin-top:22px;max-width:46ch}
hr{height:1px;border:0;margin:32px 0;opacity:.42;
  background:linear-gradient(90deg,#7B5CD6,#4FC3D9 46%,#D9AE5F 82%,transparent)}
.btn{border-radius:11px;text-decoration:none;display:inline-block;
  background:linear-gradient(165deg,#F2D9A0,#D9AE5F 58%,#8F6B27);color:#1E1403;
  font-family:'Archivo',sans-serif;font-weight:800;font-size:.88rem;text-transform:uppercase;
  letter-spacing:.09em;padding:15px 28px}
.foot{margin-top:36px;font-family:'IBM Plex Mono',monospace;font-size:.63rem;letter-spacing:.14em;
  text-transform:uppercase;color:#5D6580}
</style></head>
<body><main>
  <a href="/" class="mark">
    <svg width="20" height="14" viewBox="0 0 22 15" aria-hidden="true"><defs><linearGradient id="b" x1="0" x2="1"><stop offset="0" stop-color="#7B5CD6"/><stop offset=".5" stop-color="#4FC3D9"/><stop offset="1" stop-color="#D9AE5F"/></linearGradient></defs><path d="M1.5 13 Q11 2 20.5 13" stroke="url(#b)" stroke-width="2.4" fill="none" stroke-linecap="round"/></svg>
    SOVRAN
  </a>
  <span class="code">${ok ? "Removed · Complete" : "Nothing to remove"}</span>
  <h1>${heading}</h1>
  ${body}
  <hr>
  <a href="/" class="btn">Back to SOVRAN</a>
  <p class="foot">No cookies · No trackers · No analytics</p>
</main></body></html>`,
  { status: ok ? 200 : 404, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } }
);

async function remove(request, env) {
  const token = new URL(request.url).searchParams.get("t");

  if (!token) {
    return page("Nothing to remove", "That link is <span class='gilt'>incomplete</span>.",
      `<p>The unsubscribe link was missing its identifier — some email clients truncate long
        URLs. Reply to any email from us and we'll remove you by hand, immediately.</p>`, false);
  }

  let result;
  try {
    result = await env.DB.prepare("DELETE FROM waitlist WHERE token = ?1").bind(token).run();
  } catch {
    return page("Something went wrong", "We couldn't <span class='gilt'>complete</span> that.",
      `<p>Something failed on our side. Reply to any email from us and we'll remove you
        by hand — that always works.</p>`, false);
  }

  if (result?.meta?.changes > 0) {
    return page("Removed", "You're <span class='gilt'>gone</span>.",
      `<p>Your email address has been deleted from our database. Not flagged, not moved to a
        suppression list, not kept "for compliance" — the row is gone, and there is nothing
        left of you here.</p>
       <p>That's how it should work everywhere. It almost never does.</p>
       <p>If you ever want back in, the waitlist is always open.</p>`);
  }

  return page("Already gone", "You're <span class='gilt'>already</span> gone.",
    `<p>We have no record matching that link. Either you've already unsubscribed, or the
      link has been used before. Either way, you're not on the list.</p>`, false);
}

export const onRequestGet  = ({ request, env }) => remove(request, env);
export const onRequestPost = ({ request, env }) => remove(request, env); // RFC 8058 one-click

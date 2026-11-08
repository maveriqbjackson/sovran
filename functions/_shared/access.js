/* Cloudflare Access sign-in, checked on the server.

   Cloudflare Access sits in front of the admin pages and emails people a
   one-time code. Once they're in, Cloudflare puts a signed token in the
   CF_Authorization cookie (and the Cf-Access-Jwt-Assertion header on pages it
   covers). This file checks that token's signature against Cloudflare's public
   keys, so a request only counts as signed in if Cloudflare really signed it,
   and returns the verified email address.

   Needs two settings on this Pages project (Settings -> Variables and Secrets):
     ACCESS_TEAM_DOMAIN  e.g. aetherash.cloudflareaccess.com
     ACCESS_AUD          the Application Audience (AUD) tag of this site's Access app
                         (several allowed, separated by commas)
   Neither is a secret. Without them, nobody is signed in. */

let certCache = { at: 0, team: '', keys: null };

function b64u(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
function part(s) { return JSON.parse(new TextDecoder().decode(b64u(s))); }

function token(request) {
  const h = request.headers.get('Cf-Access-Jwt-Assertion');
  if (h) return h;
  const m = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)CF_Authorization=([^;]+)/);
  return m ? m[1] : null;
}

async function certs(team) {
  if (certCache.keys && certCache.team === team && Date.now() - certCache.at < 3600e3) return certCache.keys;
  const r = await fetch(`https://${team}/cdn-cgi/access/certs`);
  if (!r.ok) throw new Error('certs ' + r.status);
  const j = await r.json();
  certCache = { at: Date.now(), team, keys: j.keys || [] };
  return certCache.keys;
}

export async function accessEmail(request, env) {
  const team = String(env.ACCESS_TEAM_DOMAIN || '').trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const auds = String(env.ACCESS_AUD || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!team || !auds.length) return null;
  const t = token(request);
  if (!t) return null;
  const p = t.split('.');
  if (p.length !== 3) return null;
  let head, body;
  try { head = part(p[0]); body = part(p[1]); } catch { return null; }
  if (head.alg !== 'RS256') return null;
  const aud = Array.isArray(body.aud) ? body.aud : [body.aud];
  if (!aud.some((a) => auds.includes(a))) return null;
  const now = Date.now() / 1000;
  if (!body.exp || body.exp < now) return null;
  if (body.nbf && body.nbf > now + 60) return null;
  if (body.iss && body.iss !== `https://${team}`) return null;
  try {
    let jwk = (await certs(team)).find((k) => k.kid === head.kid);
    if (!jwk) { certCache.keys = null; jwk = (await certs(team)).find((k) => k.kid === head.kid); }
    if (!jwk) return null;
    const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64u(p[2]), new TextEncoder().encode(p[0] + '.' + p[1]));
    return ok && body.email ? String(body.email).trim().toLowerCase() : null;
  } catch { return null; }
}

/* Mav's two emails are owners everywhere, always. */
export const OWNERS = ['maveriqbjackson@proton.me', 'team@theqcollective.org'];
export const SIGN_IN = '/cdn-cgi/access/login';
export const SIGN_OUT = '/cdn-cgi/access/logout';

/* Why isn't this request signed in? Plain reasons for the admin check page.
   Shows nothing secret: the setting names, whether they match, and the email on
   the visitor's own sign-in token. */
export async function accessWhy(request, env) {
  const team = String(env.ACCESS_TEAM_DOMAIN || '').trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const auds = String(env.ACCESS_AUD || '').split(',').map((s) => s.trim()).filter(Boolean);
  const out = { team_setting: team || '(empty)', aud_setting_count: auds.length, token_found: false };
  const t = token(request);
  if (!t) { out.why = 'No sign-in token reached this address. The browser has no SOVRAN sign-in cookie here.'; return out; }
  out.token_found = true;
  let body = {};
  try { body = part(t.split('.')[1]); } catch { out.why = 'The sign-in token is damaged.'; return out; }
  out.email_on_token = body.email || '(none)';
  out.token_issuer = body.iss || '(none)';
  out.aud_matches = (Array.isArray(body.aud) ? body.aud : [body.aud]).some((a) => auds.includes(a));
  out.expired = !body.exp || body.exp < Date.now() / 1000;
  out.issuer_matches = !body.iss || body.iss === `https://${team}`;
  out.email_is_owner = OWNERS.includes(String(body.email || '').toLowerCase());
  out.why = !team || !auds.length ? 'ACCESS_TEAM_DOMAIN or ACCESS_AUD is empty on SOVRAN.'
    : !out.issuer_matches ? 'Team name mismatch: the token comes from ' + out.token_issuer + ' but SOVRAN expects https://' + team + '.'
    : !out.aud_matches ? 'The token is for a different Access app than the AUD tag SOVRAN has.'
    : out.expired ? 'The sign-in has expired. Sign in again.'
    : !out.email_is_owner ? 'Signed in, but with an email that is not one of Mav\'s two owner emails.'
    : 'Looks right. If this still fails, the signature check failed.';
  return out;
}

// POST /api/account   { action: register | login | logout | save | load | delete }
//
// Bindings : DB (D1 -> sovran-waitlist)
//
// ─────────────────────────────────────────────────────────────────────────────
// THE ARCHITECTURE, IN ONE PARAGRAPH
//
// The browser turns the passphrase into TWO separate keys using PBKDF2:
//
//   authKey  — derived with the salt "sovran-auth". Sent here. We hash it AGAIN
//              with a per-account salt and store only that hash. It proves who
//              you are and is useless for decryption.
//
//   dataKey  — derived with the salt "sovran-data". NEVER LEAVES THE DEVICE.
//              It encrypts the vault before upload and decrypts it after
//              download. We have never seen it and cannot compute it.
//
// So this endpoint stores: an email, a salt, a hash, and a block of ciphertext
// it cannot open. If it were dumped tomorrow, the attacker would get a mailing
// list and a pile of noise. That is the entire point.
//
// It also means there is NO PASSWORD RESET. We cannot re-encrypt what we cannot
// read. A lost passphrase is a lost vault, permanently, and the UI says so
// before anyone creates an account.
// ─────────────────────────────────────────────────────────────────────────────

const json = (obj, status = 200, headers = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store, max-age=0", ...headers },
  });

const enc = new TextEncoder();

function b64(buf) {
  const b = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

function randomHex(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return Array.from(a).map((x) => x.toString(16).padStart(2, "0")).join("");
}

// second-stage hash of the auth key, so a database dump is not directly replayable
async function hashAuth(authKey, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(authKey), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
    key, 256
  );
  return b64(bits);
}

function sameSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

const SESSION_DAYS = 30;

function cookie(token, maxAge) {
  return `sv_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

async function sessionAccount(request, env) {
  const raw = request.headers.get("Cookie") || "";
  const m = raw.match(/(?:^|;\s*)sv_session=([A-Za-z0-9]+)/);
  if (!m) return null;
  const row = await env.DB.prepare(
    "SELECT account_id, expires_at FROM sessions WHERE token = ?1"
  ).bind(m[1]).first();
  if (!row) return null;
  if (new Date(row.expires_at.replace(" ", "T") + "Z") < new Date()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?1").bind(m[1]).run();
    return null;
  }
  return { id: row.account_id, token: m[1] };
}

export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Malformed request." }, 400); }

  const action = String(body.action || "");

  try {
    /* ───────────────────────── register ───────────────────────── */
    if (action === "register") {
      const email = String(body.email || "").trim().toLowerCase();
      const authKey = String(body.authKey || "");
      const kdfSalt = String(body.kdfSalt || "");

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 254)
        return json({ error: "That email address doesn't look complete." }, 400);
      if (authKey.length < 40 || authKey.length > 200)
        return json({ error: "Something went wrong deriving your key. Reload and try again." }, 400);
      if (!kdfSalt || kdfSalt.length > 128)
        return json({ error: "Missing key material." }, 400);

      const existing = await env.DB.prepare("SELECT id FROM accounts WHERE email = ?1").bind(email).first();
      if (existing) return json({ error: "There is already an account with that email. Try signing in." }, 409);

      const id = randomHex(16);
      const authSalt = randomHex(16);
      const stored = await hashAuth(authKey, authSalt);

      await env.DB.prepare(
        `INSERT INTO accounts (id, email, kdf_salt, auth_hash, auth_salt, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
      ).bind(id, email, kdfSalt, stored, authSalt).run();

      const token = randomHex(32);
      await env.DB.prepare(
        `INSERT INTO sessions (token, account_id, expires_at)
         VALUES (?1, ?2, datetime('now', '+${SESSION_DAYS} days'))`
      ).bind(token, id).run();

      return json({ ok: true, email }, 200, { "Set-Cookie": cookie(token, SESSION_DAYS * 86400) });
    }

    /* ───────── salt lookup: needed before the browser can derive ───────── */
    if (action === "salt") {
      const email = String(body.email || "").trim().toLowerCase();
      const row = await env.DB.prepare("SELECT kdf_salt FROM accounts WHERE email = ?1").bind(email).first();
      // always answer, so this cannot be used to enumerate who has an account
      return json({ ok: true, kdfSalt: row ? row.kdf_salt : "sovran-" + email });
    }

    /* ───────────────────────── login ───────────────────────── */
    if (action === "login") {
      const email = String(body.email || "").trim().toLowerCase();
      const authKey = String(body.authKey || "");

      const acct = await env.DB.prepare(
        "SELECT id, auth_hash, auth_salt FROM accounts WHERE email = ?1"
      ).bind(email).first();

      // same delay and same message whether the account exists or not
      if (!acct) {
        await new Promise((r) => setTimeout(r, 350));
        return json({ error: "That email and passphrase do not match an account." }, 401);
      }

      const attempt = await hashAuth(authKey, acct.auth_salt);
      if (!sameSecret(attempt, acct.auth_hash)) {
        await new Promise((r) => setTimeout(r, 350));
        return json({ error: "That email and passphrase do not match an account." }, 401);
      }

      const token = randomHex(32);
      await env.DB.prepare(
        `INSERT INTO sessions (token, account_id, expires_at)
         VALUES (?1, ?2, datetime('now', '+${SESSION_DAYS} days'))`
      ).bind(token, acct.id).run();
      await env.DB.prepare("UPDATE accounts SET last_seen = datetime('now') WHERE id = ?1").bind(acct.id).run();
      // opportunistic cleanup
      await env.DB.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();

      return json({ ok: true, email }, 200, { "Set-Cookie": cookie(token, SESSION_DAYS * 86400) });
    }

    /* ───────────────────────── session-gated ───────────────────────── */
    const me = await sessionAccount(request, env);

    if (action === "whoami") {
      if (!me) return json({ ok: true, signedIn: false });
      const a = await env.DB.prepare("SELECT email FROM accounts WHERE id = ?1").bind(me.id).first();
      return json({ ok: true, signedIn: true, email: a ? a.email : null });
    }

    if (action === "logout") {
      if (me) await env.DB.prepare("DELETE FROM sessions WHERE token = ?1").bind(me.token).run();
      return json({ ok: true }, 200, { "Set-Cookie": cookie("", 0) });
    }

    if (!me) return json({ error: "Not signed in." }, 401);

    /* save an encrypted blob we cannot read */
    if (action === "save") {
      const ciphertext = String(body.ciphertext || "");
      const iv = String(body.iv || "");
      if (!ciphertext || !iv) return json({ error: "Nothing to save." }, 400);
      if (ciphertext.length > 400000) return json({ error: "That vault is too large." }, 413);

      await env.DB.prepare(
        `INSERT INTO vaults (account_id, ciphertext, iv, updated_at)
         VALUES (?1, ?2, ?3, datetime('now'))
         ON CONFLICT(account_id) DO UPDATE SET
           ciphertext = excluded.ciphertext, iv = excluded.iv, updated_at = datetime('now')`
      ).bind(me.id, ciphertext, iv).run();

      return json({ ok: true, saved_at: new Date().toISOString() });
    }

    if (action === "load") {
      const v = await env.DB.prepare(
        "SELECT ciphertext, iv, updated_at FROM vaults WHERE account_id = ?1"
      ).bind(me.id).first();
      return json({ ok: true, vault: v || null });
    }

    /* delete everything, immediately and for real */
    if (action === "delete") {
      await env.DB.prepare("DELETE FROM vaults   WHERE account_id = ?1").bind(me.id).run();
      await env.DB.prepare("DELETE FROM sessions WHERE account_id = ?1").bind(me.id).run();
      await env.DB.prepare("DELETE FROM accounts WHERE id = ?1").bind(me.id).run();
      return json({ ok: true }, 200, { "Set-Cookie": cookie("", 0) });
    }

    return json({ error: "Unknown action." }, 400);
  } catch (err) {
    return json({ error: "Something failed on our side. Try again in a moment." }, 500);
  }
}

export const onRequestGet    = () => json({ error: "Method not allowed." }, 405);
export const onRequestPut    = () => json({ error: "Method not allowed." }, 405);
export const onRequestPatch  = () => json({ error: "Method not allowed." }, 405);
export const onRequestDelete = () => json({ error: "Method not allowed." }, 405);

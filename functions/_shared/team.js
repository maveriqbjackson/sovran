/* Who can sign SOVRAN's canary. The list lives in Mav HQ's People screen
   (aetherandash.digital/hq), so adding or removing a signer there updates it here
   within a minute. Mav's own emails can always sign.
   Needs TEAM_SYNC_KEY (the same secret on this site and aetherandash.digital). */
import { accessEmail, OWNERS } from './access.js';

let cache = { at: 0, people: null };

async function signers(env) {
  if (cache.people && Date.now() - cache.at < 60e3) return cache.people;
  if (!env.TEAM_SYNC_KEY) return [];
  try {
    const r = await fetch('https://aetherandash.digital/api/team/roles?area=sovran_canary', { headers: { 'x-team-key': env.TEAM_SYNC_KEY } });
    if (!r.ok) return cache.people || [];
    const j = await r.json();
    cache = { at: Date.now(), people: j.people || [] };
    return cache.people;
  } catch { return cache.people || []; }
}

/* { email, role: 'signer' | 'witness' | null, name } for whoever is signed in. */
export async function canaryRole(request, env) {
  const email = await accessEmail(request, env);
  if (!email) return { email: null, role: null, name: null };
  if (OWNERS.includes(email)) return { email, role: 'signer', name: 'Mav' };
  const p = (await signers(env)).find((x) => String(x.email).toLowerCase() === email);
  return { email, role: p ? p.role : null, name: p ? p.name : null };
}

export async function isOwner(request, env) {
  const email = await accessEmail(request, env);
  return email && OWNERS.includes(email) ? email : null;
}

// api/_auth.js — Google ID token verification
// Verifies Authorization: Bearer <googleIdToken> header server-side.

const GOOGLE_TOKENINFO = 'https://oauth2.googleapis.com/tokeninfo?id_token=';
const EXPECTED_CLIENT_ID = '1010698547754-h3pfeegsn3tkemksjjtjlcgccoqtqbt6.apps.googleusercontent.com';

// AUTHORIZED USERS: elizabeth, cliff, henry only
export const ALLOWED_EMAILS = [
  'elizabeth@tigertracks.ai',
  'cliff@tigertracks.ai',
  'henry@tigertracks.ai',
];

export async function getAuthenticatedEmail(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7).trim();
  if (!token) return null;

  try {
    const r = await fetch(`${GOOGLE_TOKENINFO}${token}`);
    if (!r.ok) return null;
    const info = await r.json();

    if (info.aud !== EXPECTED_CLIENT_ID) return null;
    const email = (info.email || '').toLowerCase();
    if (!ALLOWED_EMAILS.includes(email)) return null;
    if (parseInt(info.exp) < Math.floor(Date.now() / 1000)) return null;

    return email;
  } catch {
    return null;
  }
}

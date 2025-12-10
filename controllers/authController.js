// Dev auth controller enhanced: issues JWT and sets a cookie usable by keysMiddleware
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret';
const APP_SECRET = process.env.APP_SECRET || '';

// Optional Prisma client — load lazily and handle absence
let prisma = null;
try {
  const { PrismaClient } = await import('@prisma/client');
  prisma = new PrismaClient();
} catch (e) {
  prisma = null;
}

function makeCookieToken(payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
  if (!APP_SECRET) return token;
  const hmac = crypto.createHmac('sha256', APP_SECRET).update(token).digest('hex');
  return `${hmac}:${token}`;
}

// Ensure we have a stable 32-byte key for AES-256 from env or derived from secrets
function getCryptoKey() {
  const raw = process.env.CRYPTO_KEY || (JWT_SECRET + APP_SECRET);
  return crypto.createHash('sha256').update(String(raw)).digest(); // 32 bytes
}

// Encrypts the JWT and returns a base64 dot-separated string iv.tag.cipher[.pad...]
function encryptLongJWT(token, targetLen = 2000) {
  const key = getCryptoKey();
  const iv = crypto.randomBytes(12); // GCM recommended 12 bytes
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const payload = JSON.stringify({ token });
  let encrypted = cipher.update(payload, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const tag = cipher.getAuthTag().toString('base64');

  let out = `${iv.toString('base64')}.${tag}.${encrypted}`;

  // Append random base64 segments until we reach target length (safe padding)
  while (out.length < targetLen) {
    out += '.' + crypto.randomBytes(32).toString('base64');
  }

  return out;
}

function decryptLongJWT(encrypted) {
  try {
    const parts = encrypted.split('.');
    if (parts.length < 3) return null;
    const iv = Buffer.from(parts[0], 'base64');
    const tag = Buffer.from(parts[1], 'base64');
    const ciphertext = parts[2];
    const key = getCryptoKey();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    const parsed = JSON.parse(decrypted);
    return parsed && parsed.token ? parsed.token : null;
  } catch (e) {
    return null;
  }
}

// Update login function to encrypt JWT with long output and include unique jti
export async function login(req, res, next) {
  try {
    console.log('>>> POST /api/auth/login called', { body: req.body });
    const { password } = req.body || {};
    const identifier = req.body.identifier || req.body.username || req.body.email;
    if (!identifier || !password) return res.status(400).json({ error: 'Missing identifier or password' });

    let user = null;
    if (prisma) {
      user = await prisma.user.findUnique({ where: { username: identifier } }).catch(() => null);
      if (!user) {
        user = await prisma.user.findUnique({ where: { email: identifier } }).catch(() => null);
      }
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });

      if (!user.password) return res.status(401).json({ error: 'Invalid credentials' });
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    } else {
      if (password !== 'password') return res.status(401).json({ error: 'Invalid credentials' });
      user = { id: `local-${Date.now()}`, username: identifier, isPremium: false, userType: 'NORMAL' };
    }

    // Create JWT with a unique jti so the signed value changes each login
    const jwtPayload = { sub: user.id, username: user.username, jti: crypto.randomBytes(16).toString('hex') };
    const accessToken = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '7d' });

    // Encrypt the JWT before setting the cookie
    const encryptedToken = encryptLongJWT(accessToken, 2000);

    // Set the HttpOnly cookie (store the encrypted token instead of raw JWT)
    const cookieName = process.env.AUTH_COOKIE_NAME || 'Love_wins_Whats_up_with_that';
    res.cookie(cookieName, encryptedToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 7,
      path: '/',
    });

    // Ensure Priority=High on headers and log for debugging
    ensurePriorityOnSetCookie(res);
    console.log('authController.login set cookie:', cookieName);

    // Return long encrypted token for client-side use (already used as cookie)
    console.log('    login OK - returning user for', identifier);
    return res.json({ ok: true, user, token: encryptedToken });
  } catch (err) {
    console.error('ERROR in authController.login', err);
    return next(err);
  }
}

// Update register similarly
export async function register(req, res, next) {
  try {
    console.log('>>> POST /api/auth/register called', { body: req.body });
    const {
      username,
      email,
      password,
      firstName,
      lastName,
      phone,
      avatar,
      userType,
      isPremium,
    } = req.body || {};

    if ((!username && !email) || !password) return res.status(400).json({ error: 'Missing username/email or password' });

    let user = null;
    if (prisma) {
      const emailVal = email || (username && username.includes('@') ? username : null);
      const usernameVal = username || (emailVal ? emailVal.split('@')[0] : `user_${Date.now()}`);

      const existsByUsername = await prisma.user.findUnique({ where: { username: usernameVal } }).catch(() => null);
      const existsByEmail = emailVal ? await prisma.user.findUnique({ where: { email: emailVal } }).catch(() => null) : null;
      if (existsByUsername || existsByEmail) return res.status(409).json({ error: 'User already exists' });

      const hashed = await bcrypt.hash(password, 10);
      const createData = { username: usernameVal, email: emailVal, password: hashed };
      if (firstName) createData.firstName = firstName;
      if (lastName) createData.lastName = lastName;
      if (phone) createData.phone = phone;
      if (avatar) createData.avatar = avatar;
      if (typeof isPremium !== 'undefined') createData.isPremium = Boolean(isPremium);
      if (userType) createData.userType = userType;

      user = await prisma.user.create({ data: createData }).catch((e) => {
        console.error('prisma.create user error', e?.message || e);
        return null;
      });

      if (!user) return res.status(500).json({ error: 'Failed to create user' });
    } else {
      user = {
        id: `local-${Date.now()}`,
        username: username || email || `user_${Date.now()}`,
        email: email || null,
        firstName: firstName || null,
        lastName: lastName || null,
        phone: phone || null,
        avatar: avatar || null,
        isPremium: Boolean(isPremium) || false,
        userType: userType || 'NORMAL',
      };
    }

    // Create JWT with unique jti
    const jwtPayload = { sub: user.id, username: user.username, jti: crypto.randomBytes(16).toString('hex') };
    const accessToken = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '7d' });

    // Encrypt token and set encrypted cookie (do not set raw JWT)
    const encryptedToken = encryptLongJWT(accessToken, 2000);
    const cookieName = process.env.AUTH_COOKIE_NAME || 'Love_wins_Whats_up_with_that';
    res.cookie(cookieName, encryptedToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 7,
      path: '/',
    });

    // Ensure Priority=High on headers and log for debugging
    ensurePriorityOnSetCookie(res);
    console.log('authController.register set cookie:', cookieName);

    console.log('    register OK - returning user', user.username);
    return res.status(201).json({ ok: true, user, token: encryptedToken });
  } catch (err) {
    console.error('ERROR in authController.register', err);
    return next(err);
  }
}

// Provide logout that clears the actual cookie used
export async function logout(req, res, next) {
  // Defensive logout: attempt to clear known cookie names but never throw
  // an internal server error to the client for logout operations. Log any
  // internal problems for debugging and return 200 so frontend UX is not
  // interrupted by server-side cookie-clearing edge cases.
  try {
    const cookieName = process.env.AUTH_COOKIE_NAME || 'Love_wins_Whats_up_with_that';
    const extraCookieNames = [
      "Power_doesn't_sleep_fetchUser_",
      "The_now_and_the_never",
      "Legacy_whats_it_mean",
      "Joy_in_the_cracks",
      "Talk_back_to_the_past",
      "We_dont_sleep_we_dream",
      "The_questions_stay_louder",
    ];
    const cookieNamesToClear = [cookieName, ...extraCookieNames, 'jwt', 'token', 'Love_wins_Whats_up_with_that'];

    const isProd = process.env.NODE_ENV === 'production';
    const secure = !!(req.secure || (req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'].includes('https')) || isProd);
    const sameSite = secure ? 'None' : 'Lax';

    console.log('authController.logout start, attempting to clear cookies:', cookieNamesToClear);

    cookieNamesToClear.forEach((name) => {
      try {
        // best-effort clear without domain
        res.clearCookie(name, { path: '/', httpOnly: true, secure, sameSite });
      } catch (e) {
        console.warn('authController.logout: clearCookie failed for', name, e && e.message ? e.message : e);
      }

      if (process.env.COOKIE_DOMAIN) {
        try {
          const d = process.env.COOKIE_DOMAIN;
          res.clearCookie(name, { path: '/', domain: d, httpOnly: true, secure, sameSite });
          const dot = d.startsWith('.') ? d : `.${d}`;
          res.clearCookie(name, { path: '/', domain: dot, httpOnly: true, secure, sameSite });
        } catch (e) {
          console.warn('authController.logout: domain clearCookie failed for', name, e && e.message ? e.message : e);
        }
      }
    });

    // best-effort clear server-side session
    try {
      if (req.session && typeof req.session.destroy === 'function') req.session.destroy(() => {});
    } catch (e) {
      console.warn('authController.logout: session.destroy failed', e && e.message ? e.message : e);
    }

    // Always return 200 for logout to avoid a blocking UX; detailed errors
    // will be present in server logs.
    return res.status(200).json({ ok: true, message: 'Logged out' });
  } catch (err) {
    console.error('authController.logout unexpected error', err && err.stack ? err.stack : err);
    // Still return 200 to the client to prevent the frontend showing a 500
    // — this operation is best-effort and should not block the user.
    return res.status(200).json({ ok: false, message: 'Logout attempted but encountered server-side issues' });
  }
}

// --- Bluesky OAuth helpers ---
function buildBlueskyAuthorizeUrl(state, code_challenge) {
  const authUrl = process.env.BLUESKY_AUTH_URL || 'https://bsky.social/oauth/authorize';
  // Use the BLUESKY_CLIENT_ID exactly as configured by the developer.
  // The provider must accept whatever value the app was registered with.
  const clientId = process.env.BLUESKY_CLIENT_ID || '';
  const originalRedirect = process.env.BLUESKY_REDIRECT_URI || `${process.env.CLIENT_URL || 'http://127.0.0.1:9234'}/auth/bluesky/callback`;
  // Canonicalize localhost to loopback IP to satisfy RFC8252 and provider checks
  let redirect = originalRedirect;
  try {
    const parsed = new URL(originalRedirect);
    if (parsed.hostname === 'localhost') {
      parsed.hostname = '127.0.0.1';
      // preserve port and pathname
      redirect = parsed.toString();
    }
  } catch (e) {
    redirect = originalRedirect;
  }

  const scope = process.env.BLUESKY_SCOPE || 'openid email profile';
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirect,
    scope,
    state,
  });

  if (code_challenge) {
    params.set('code_challenge', code_challenge);
    params.set('code_challenge_method', 'S256');
  }

  console.log('Original Redirect URI:', originalRedirect);
  console.log('Canonicalized Redirect URI:', redirect);
  console.log('Using client_id:', clientId);
  console.log('Full Authorize URL:', `${authUrl}?${params.toString()}`);

  return `${authUrl}?${params.toString()}`;
}

export async function blueskyStart(req, res, next) {
  try {
    // Validate configuration early
    const clientId = process.env.BLUESKY_CLIENT_ID;
    const redirectUri = process.env.BLUESKY_REDIRECT_URI || `${process.env.CLIENT_URL || 'http://localhost:9234'}/auth/bluesky/callback`;
    if (!clientId) {
      console.error('BLUESKY_CLIENT_ID is not configured in environment');
      return res.status(500).json({ error: 'BLUESKY_CLIENT_ID not configured on server' });
    }

  // Create a simple state to validate callback (could be improved with session)
  const state = crypto.randomBytes(12).toString('hex');

  // PKCE: generate code_verifier and code_challenge (S256)
  const code_verifier = crypto.randomBytes(64).toString('base64url');
  const sha = crypto.createHash('sha256').update(code_verifier).digest();
  const code_challenge = Buffer.from(sha).toString('base64url');

  // For simple dev flow, store state and verifier in short-lived HttpOnly cookies
  res.cookie('bluesky_oauth_state', state, { httpOnly: true, maxAge: 1000 * 60 * 5, path: '/' });
  res.cookie('bluesky_code_verifier', code_verifier, { httpOnly: true, maxAge: 1000 * 60 * 5, path: '/' });

  const url = buildBlueskyAuthorizeUrl(state, code_challenge);

    // Log the exact URL for diagnostics
    console.log('blueskyStart redirect URL:', url);

    // In development, show a debug page with the full URL so you can inspect it before redirecting
    if (process.env.NODE_ENV !== 'production') {
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>Bluesky OAuth Debug</title></head><body>
        <h2>Bluesky OAuth Debug</h2>
        <p>Authorize URL (copied below). If you get a 400 from the provider, compare this redirect_uri with the one registered in the provider console.</p>
        <pre style="white-space:pre-wrap;word-break:break-all;">${url}</pre>
        <p><a href="${url}">Continue to Bluesky (follow this link)</a></p>
        </body></html>`;
      res.setHeader('Content-Type', 'text/html');
      return res.send(html);
    }

    return res.redirect(url);
  } catch (err) {
    next(err);
  }
}

async function exchangeCodeForToken(code, code_verifier) {
  const tokenUrl = process.env.BLUESKY_TOKEN_URL || 'https://bsky.social/oauth/token';
  const clientId = process.env.BLUESKY_CLIENT_ID || '';
  const clientSecret = process.env.BLUESKY_CLIENT_SECRET || '';

  // Canonicalize redirect URI (use loopback IP instead of 'localhost' when present)
  const originalRedirect = process.env.BLUESKY_REDIRECT_URI || `${process.env.CLIENT_URL || 'http://127.0.0.1:9234'}/auth/bluesky/callback`;
  let redirect = originalRedirect;
  try {
    const parsed = new URL(originalRedirect);
    if (parsed.hostname === 'localhost') parsed.hostname = '127.0.0.1';
    redirect = parsed.toString();
  } catch (e) {
    redirect = originalRedirect;
  }

  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirect,
  });

  if (code_verifier) params.set('code_verifier', code_verifier);

  // Use fetch (available in Node 18+), fallback to axios if necessary
  if (typeof fetch !== 'undefined') {
    const r = await fetch(tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params.toString() });
    const text = await r.text();
    let parsed = null;
    try { parsed = text ? JSON.parse(text) : null; } catch (e) { /* ignore JSON parse errors */ }
    if (!r.ok) {
      console.error('exchangeCodeForToken failed', { status: r.status, statusText: r.statusText, body: parsed || text });
      const msg = parsed && parsed.error_description ? `${parsed.error_description}` : (parsed && parsed.error ? parsed.error : text || r.statusText);
      const err = new Error(`token exchange failed: ${msg}`);
      err.response = { status: r.status, body: parsed || text };
      throw err;
    }
    return parsed || JSON.parse(text);
  }
  // fallback: use axios
  const axios = (await import('axios')).default;
  try {
    const resp = await axios.post(tokenUrl, params.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    return resp.data;
  } catch (e) {
    console.error('exchangeCodeForToken axios error', e?.response?.status, e?.response?.data || e.message);
    throw e;
  }
}

export async function blueskyCallback(req, res, next) {
  try {
    const { code, state } = req.query || {};
    const saved = req.cookies && req.cookies['bluesky_oauth_state'];
    if (!code) return res.status(400).send('Missing code');
    if (!saved || saved !== state) {
      // warn but continue in dev if APP_SECRET not set
      if (process.env.NODE_ENV === 'production') return res.status(400).send('Invalid state');
    }

  // Read code_verifier from cookie (set by blueskyStart)
  const code_verifier = req.cookies && req.cookies['bluesky_code_verifier'];
  let tokenResp = null;
  try {
    tokenResp = await exchangeCodeForToken(code, code_verifier);
  } catch (e) {
    console.error('blueskyCallback token exchange error:', e?.message || e);
    // If provider returned structured response, encode it back to frontend for debugging
    const body = e?.response?.body || e?.message || 'unknown_error';
    const frontErr = encodeURIComponent(typeof body === 'object' ? JSON.stringify(body) : String(body));
    const front = process.env.CLIENT_URL || process.env.DEV_CLIENT_URL || 'http://localhost:9234';
    // In production, don't leak provider internals in the URL; instead return 500
    if (process.env.NODE_ENV === 'production') return res.status(500).send('Token exchange failed');
    return res.redirect(`${front}/?auth=bluesky_error&provider_error=${frontErr}`);
  }
  // Clear short-lived PKCE/state cookies now that exchange completed
  try {
    res.clearCookie('bluesky_oauth_state', { path: '/' });
    res.clearCookie('bluesky_code_verifier', { path: '/' });
  } catch (e) {
    // ignore
  }
    // tokenResp should contain access_token and possibly id_token/profile info
    const accessToken = tokenResp.access_token || tokenResp.token;
    const idToken = tokenResp.id_token || null;

    // Try to get user info from provider (if a userinfo endpoint exists)
    let profile = null;
    if (tokenResp && tokenResp.access_token && process.env.BLUESKY_USERINFO_URL) {
      try {
        const r = await fetch(process.env.BLUESKY_USERINFO_URL, { headers: { Authorization: `Bearer ${tokenResp.access_token}` } });
        if (r.ok) profile = await r.json();
      } catch (e) { /* ignore */ }
    }

    // Derive a minimal user representation
    const externalId = profile?.sub || profile?.id || (profile && (profile.handle || profile.username)) || (idToken ? idToken.sub || null : null) || `bsky-${crypto.createHash('sha1').update(accessToken || String(Date.now())).digest('hex')}`;
    const username = profile?.preferred_username || profile?.username || profile?.handle || externalId;
    const email = profile?.email || null;

    // Upsert user into Prisma if available
    let user = null;
    if (prisma) {
      try {
        const existing = await prisma.user.findUnique({ where: { username } }).catch(() => null) || (email ? await prisma.user.findUnique({ where: { email } }).catch(() => null) : null);
        if (existing) {
          user = existing;
        } else {
          user = await prisma.user.create({ data: { username: username || externalId, email: email || null, isPremium: false, userType: 'NORMAL' } }).catch(() => null);
        }
      } catch (e) {
        console.error('blueskyCallback prisma error', e);
      }
    } else {
      user = { id: `bsky-${Date.now()}`, username: username || externalId, email };
    }

    // Create JWT and set encrypted cookie similarly to login/register
    const jwtPayload = { sub: user.id, username: user.username, provider: 'bluesky', jti: crypto.randomBytes(16).toString('hex') };
    const accessJwt = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '7d' });
    const encryptedToken = encryptLongJWT(accessJwt, 2000);
    const cookieName = process.env.AUTH_COOKIE_NAME || 'Love_wins_Whats_up_with_that';
    res.cookie(cookieName, encryptedToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 7,
      path: '/',
    });
    ensurePriorityOnSetCookie(res);

    // Redirect back to frontend (optionally with token fragment)
    const front = process.env.CLIENT_URL || process.env.DEV_CLIENT_URL || 'http://localhost:9234';
    // for SPAs it's common to redirect with a short-lived flag
    return res.redirect(`${front}/?auth=bluesky_success`);
  } catch (err) {
    console.error('ERROR in blueskyCallback', err);
    return next(err);
  }
}

// --- Google OAuth helpers ---
async function exchangeCodeForGoogleToken(code, code_verifier) {
  const tokenUrl = 'https://oauth2.googleapis.com/token';
  const clientId = process.env.GOOGLE_CLIENT_ID || '';
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET || '';

  // Prefer explicit GOOGLE_REDIRECT_URI; default to app client + backend callback
  const originalRedirect = process.env.GOOGLE_REDIRECT_URI || `${process.env.CLIENT_URL || 'http://localhost:9234'}/api/auth/google/callback`;
  // Canonicalize to use 'localhost' hostname if present (user prefers localhost)
  let redirect = originalRedirect;
  try {
    const parsed = new URL(originalRedirect);
    if (parsed.hostname === '127.0.0.1') parsed.hostname = 'localhost';
    redirect = parsed.toString();
  } catch (e) {
    redirect = originalRedirect;
  }

  const params = new URLSearchParams({
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirect,
    grant_type: 'authorization_code'
  });

  // If PKCE verifier provided
  if (code_verifier) params.set('code_verifier', code_verifier);

  // Use fetch (Node 18+). Throws on non-2xx
  const r = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  });

  const text = await r.text();
  let parsed = null;
  try { parsed = text ? JSON.parse(text) : null; } catch (e) { parsed = text; }
  if (!r.ok) {
    const msg = parsed && parsed.error_description ? parsed.error_description : (parsed && parsed.error ? parsed.error : text || r.statusText);
    const err = new Error(`Google token exchange failed: ${msg}`);
    err.response = { status: r.status, body: parsed || text };
    throw err;
  }
  return parsed;
}

export async function googleStart(req, res, next) {
  try {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (!clientId) {
      console.error('GOOGLE_CLIENT_ID is not configured');
      return res.status(500).json({ error: 'GOOGLE_CLIENT_ID not configured on server' });
    }

    // state + PKCE
    const state = crypto.randomBytes(12).toString('hex');
    const code_verifier = crypto.randomBytes(64).toString('base64url');
    const sha = crypto.createHash('sha256').update(code_verifier).digest();
    const code_challenge = Buffer.from(sha).toString('base64url');

    // Store short-lived cookies for state + verifier
    res.cookie('google_oauth_state', state, { httpOnly: true, maxAge: 1000 * 60 * 5, path: '/' });
    res.cookie('google_code_verifier', code_verifier, { httpOnly: true, maxAge: 1000 * 60 * 5, path: '/' });

    // If the frontend requested a popup flow, mark it so the callback can respond with a 200 HTML that notifies the opener
    const isPopup = String(req.query?.popup || req.query?.mode || '').toLowerCase() === 'true';
    if (isPopup) {
      // short-lived flag; HttpOnly is fine because the server will read it during the callback
      res.cookie('google_oauth_popup', '1', { httpOnly: true, maxAge: 1000 * 60 * 5, path: '/' });
    }

    // Build authorize URL (use localhost redirect canonicalization handled in token exchange)
    const authBase = 'https://accounts.google.com/o/oauth2/v2/auth';
    const redirectUri = process.env.GOOGLE_REDIRECT_URI || `${process.env.CLIENT_URL || 'http://localhost:9234'}/api/auth/google/callback`;
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: process.env.GOOGLE_SCOPE || 'openid email profile',
      state,
      code_challenge,
      code_challenge_method: 'S256',
      access_type: 'offline',
      prompt: 'consent'
    });

    const url = `${authBase}?${params.toString()}`;
    console.log('googleStart redirect URL:', url);

    if (process.env.NODE_ENV !== 'production') {
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>Google OAuth Debug</title></head><body>
        <h2>Google OAuth Debug</h2>
        <pre style="white-space:pre-wrap;word-break:break-all;">${url}</pre>
        <p><a href="${url}">Continue to Google (follow this link)</a></p>
        </body></html>`;
      res.setHeader('Content-Type', 'text/html');
      return res.send(html);
    }

    return res.redirect(url);
  } catch (err) {
    next(err);
  }
}

export async function googleCallback(req, res, next) {
  try {
    const { code, state } = req.query || {};
    const saved = req.cookies && req.cookies['google_oauth_state'];
    if (!code) return res.status(400).send('Missing code');
    if (!saved || saved !== state) {
      if (process.env.NODE_ENV === 'production') return res.status(400).send('Invalid state');
      // warn and continue in dev
      console.warn('googleCallback: state mismatch (continuing in dev)', { saved, state });
    }

    const code_verifier = req.cookies && req.cookies['google_code_verifier'];
    let tokenResp = null;
    try {
      tokenResp = await exchangeCodeForGoogleToken(code, code_verifier);
    } catch (e) {
      console.error('googleCallback token exchange error:', e?.message || e);
      const body = e?.response?.body || e?.message || 'unknown_error';
      const frontErr = encodeURIComponent(typeof body === 'object' ? JSON.stringify(body) : String(body));
      const front = process.env.CLIENT_URL || process.env.DEV_CLIENT_URL || 'http://localhost:9234';
      if (process.env.NODE_ENV === 'production') return res.status(500).send('Token exchange failed');
      return res.redirect(`${front}/?auth=google_error&provider_error=${frontErr}`);
    }

    // Clear short-lived PKCE/state cookies
    try {
      res.clearCookie('google_oauth_state', { path: '/' });
      res.clearCookie('google_code_verifier', { path: '/' });
    } catch (e) { /* ignore */ }

    const accessToken = tokenResp.access_token;
    const idToken = tokenResp.id_token || null;

    // Fetch userinfo from Google
    let profile = null;
    if (accessToken) {
      try {
        const r = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: `Bearer ${accessToken}` } });
        if (r.ok) profile = await r.json();
      } catch (e) { /* ignore */ }
    }

    // Derive minimal user representation
    const externalId = profile?.sub || (idToken ? (JSON.parse(Buffer.from(String(idToken).split('.')[1] || '', 'base64').toString('utf8')).sub) : null) || `google-${crypto.createHash('sha1').update(accessToken || String(Date.now())).digest('hex')}`;
    const username = profile?.email?.split?.('@')?.[0] || profile?.name || externalId;
    const email = profile?.email || null;

    // Upsert into Prisma if available
    let user = null;
    if (prisma) {
      try {
        const existing = await prisma.user.findUnique({ where: { email } }).catch(() => null) || await prisma.user.findUnique({ where: { username } }).catch(() => null);
        if (existing) {
          user = existing;
        } else {
          user = await prisma.user.create({ data: { username: username || externalId, email: email || null, isPremium: false, userType: 'NORMAL' } }).catch(() => null);
        }
      } catch (e) {
        console.error('googleCallback prisma error', e);
      }
    } else {
      user = { id: `google-${Date.now()}`, username: username || externalId, email };
    }

    // Create JWT and set encrypted cookie
    const jwtPayload = { sub: user.id, username: user.username, provider: 'google', jti: crypto.randomBytes(16).toString('hex') };
    const accessJwt = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '7d' });
    const encryptedToken = encryptLongJWT(accessJwt, 2000);
    const cookieName = process.env.AUTH_COOKIE_NAME || 'Love_wins_Whats_up_with_that';
    res.cookie(cookieName, encryptedToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 7,
      path: '/',
    });
    ensurePriorityOnSetCookie(res);

    // If this was a popup flow, respond with a small HTML page (200 OK) that posts a message to the opener and closes.
    const front = process.env.CLIENT_URL || process.env.DEV_CLIENT_URL || 'http://localhost:9234';
    const wasPopup = req.cookies && req.cookies['google_oauth_popup'];
    try {
      if (wasPopup) {
        // Clear popup flag cookie
        res.clearCookie('google_oauth_popup', { path: '/' });
        // Return HTML that notifies the opener and closes the popup
        const html = `<!doctype html><html><head><meta charset="utf-8"><title>Auth Success</title></head><body>
          <script>
            try {
              window.opener.postMessage({ auth: 'google_success' }, '${front}');
            } catch (e) { /* ignore */ }
            // close the popup
            window.close();
          </script>
          <p>Authentication successful. You can close this window.</p>
        </body></html>`;
        res.setHeader('Content-Type', 'text/html');
        return res.status(200).send(html);
      }
    } catch (e) {
      // ignore any errors preparing popup response and fallback to redirect
    }

    return res.redirect(`${front}/?auth=google_success`);
  } catch (err) {
    console.error('ERROR in googleCallback', err);
    return next(err);
  }
}

// Debug endpoint: report canonicalized client_id and try fetching common metadata endpoints
export async function blueskyDebugClient(req, res, next) {
  try {
    const rawClientId = process.env.BLUESKY_CLIENT_ID || '';
    let canonicalClientId = rawClientId;
    try {
      if (canonicalClientId && !canonicalClientId.startsWith('http://') && !canonicalClientId.startsWith('https://') && /^[a-z0-9.-]+$/i.test(canonicalClientId)) {
        canonicalClientId = `https://${canonicalClientId}`;
      }
    } catch (e) {
      // ignore
    }

    const authUrl = process.env.BLUESKY_AUTH_URL || 'https://bsky.social/oauth/authorize';
    const tokenUrl = process.env.BLUESKY_TOKEN_URL || 'https://bsky.social/oauth/token';

    const results = [];
    // Try fetching well-known OpenID configuration on the canonical client host
    try {
      const wellKnown = new URL('/.well-known/openid-configuration', canonicalClientId).toString();
      const r = await fetch(wellKnown, { method: 'GET' });
      const text = await r.text();
      let body = null;
      try { body = text ? JSON.parse(text) : null; } catch (e) { body = text; }
      results.push({ target: wellKnown, ok: r.ok, status: r.status, body: body });
    } catch (e) {
      results.push({ target: `${canonicalClientId}/.well-known/openid-configuration`, ok: false, error: String(e) });
    }

    // Check the configured auth and token endpoints
    async function probe(url) {
      try {
        const r = await fetch(url, { method: 'GET' });
        const txt = await r.text();
        let p = null;
        try { p = txt ? JSON.parse(txt) : null; } catch (e) { p = txt; }
        return { target: url, ok: r.ok, status: r.status, body: p };
      } catch (e) {
        return { target: url, ok: false, error: String(e) };
      }
    }

    results.push(await probe(authUrl));
    results.push(await probe(tokenUrl));

    return res.json({ originalClientId: rawClientId, canonicalClientId, authUrl, tokenUrl, probes: results });
  } catch (e) {
    console.error('blueskyDebugClient error', e);
    return res.status(500).json({ error: String(e) });
  }
}

function ensurePriorityOnSetCookie(res) {
  const sc = res.getHeader('Set-Cookie');
  if (!sc) return;
  const arr = Array.isArray(sc) ? sc : [sc];
  const withPriority = arr.map(s => (String(s).includes('Priority=') ? s : `${s}; Priority=High`));
  res.setHeader('Set-Cookie', withPriority);
}


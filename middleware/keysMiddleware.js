import crypto from 'crypto';

// Simple middleware: expects a cookie named "Love_wins_Whats_up_with_that" to contain an encrypted set of keys
export default function keysMiddleware(req, res, next) {
  const cookie = req.cookies['Love_wins_Whats_up_with_that'];
  if (!cookie) return res.status(401).json({ error: 'Unauthorized - missing keys' });

  try {
    // decrypt with server secret if set, otherwise accept presence
    const secret = process.env.APP_SECRET || '';
    if (secret && cookie) {
      // attempt a simple HMAC validation encoded as hex: format expected: hmac:payload
      const [hmac, payload] = cookie.split(':');
      const calc = crypto.createHmac('sha256', secret).update(payload || '').digest('hex');
      if (calc !== hmac) return res.status(401).json({ error: 'Unauthorized - invalid keys' });
    }
    // allow through if present
    next();
  } catch (err) {
    next(err);
  }
}

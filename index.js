import express from "express";
import { LRUCache } from "lru-cache";
import sanitizeHtml from "sanitize-html";
import cors from "cors";
import cookieParser from "cookie-parser";
import { readFile } from 'fs/promises';
import dotenv from "dotenv";
import hpp from "hpp";
import helmet from "helmet"; // Security headers
import userRoutes from './routes/userRoutes.js';
import keysMiddleware from './middleware/keysMiddleware.js';
import authRoutes from './routes/authRoutes.js';
import * as authController from './controllers/authController.js';
import bodyParser from "body-parser";
import http from 'http';
import { Server as IOServer } from 'socket.io';
import Stripe from "stripe";

// Import Routes


// Load Environment Variables
dotenv.config(); // Ensure this loads your .env file

// Powerful caching and async request coalescing example
const cache = new LRUCache({
  max: 100, // max items
  ttl: 1000 * 60 * 5 // 5 minutes
});

// Example: cache API results to avoid duplicate requests
// app.get('/api/data', async (req, res) => {
//   const key = req.query.id;
//   let result = cache.get(key);
//   if (!result) {
//     result = await fetchDataFromDbOrApi(key);
//     cache.set(key, result);
//   }
//   res.json(result);
// });

const stripe = new Stripe(process.env.STRIPE_API_KEY);

const app = express();

// Serve static files from the `public` folder (including .well-known metadata)
// This makes `http://<host>/.well-known/client-metadata.json` available when running locally.
const path = await import('path');
const publicDir = path.resolve(process.cwd(), 'public');
app.use(express.static(publicDir));

// Explicitly serve client metadata at a known path in case static middleware
// doesn't resolve because of path edge-cases with .well-known on some systems.
app.get('/.well-known/client-metadata.json', (req, res) => {
  const metaPath = path.join(publicDir, '.well-known', 'client-metadata.json');
  res.sendFile(metaPath, (err) => {
    if (err) {
      // common case: file doesn't exist or permission error
      console.warn('sendFile error for client-metadata.json:', err && err.message ? err.message : err);
      // Fallback: try reading the file directly and send contents. This works around some platform/path
      // edge-cases where res.sendFile may fail even though the file exists on disk.
      (async () => {
        try {
          const buf = await readFile(metaPath, { encoding: 'utf8' });
          res.type('application/json').send(buf);
        } catch (readErr) {
          console.warn('Fallback readFile also failed for client-metadata.json:', readErr && readErr.message ? readErr.message : readErr);
          res.status(err.status || 404).json({ error: 'client-metadata.json not found', path: metaPath, message: err.message });
        }
      })();
    }
  });
});

// Extra explicit endpoint that returns the metadata JSON by reading the file (useful when sendFile fails)
app.get('/api/auth/bluesky/metadata-inline', async (req, res) => {
  const metaPath = path.join(publicDir, '.well-known', 'client-metadata.json');
  try {
    const buf = await readFile(metaPath, { encoding: 'utf8' });
    res.type('application/json').send(buf);
  } catch (err) {
    console.error('GET /api/auth/bluesky/metadata-inline failed:', err && err.message ? err.message : err);
    res.status(404).json({ exists: false, metaPath, message: String(err) });
  }
});

// ESM-friendly fs import and Debug: report metadata file availability and BLUESKY_CLIENT_ID env at runtime
import { existsSync } from 'fs';

app.get('/api/auth/bluesky/metadata-info', (req, res) => {
  try {
    const metaPath = path.join(publicDir, '.well-known', 'client-metadata.json');
    const exists = existsSync(metaPath);
    return res.json({ exists, metaPath, BLUESKY_CLIENT_ID: process.env.BLUESKY_CLIENT_ID || null });
  } catch (err) {
    console.error('Error in /api/auth/bluesky/metadata-info:', err && err.stack ? err.stack : err);
    return res.status(500).json({ error: 'Unable to check metadata file', detail: String(err) });
  }
});

// <-- Improve middleware to enforce Priority=High on all Set-Cookie headers (covers setHeader, append, and res.cookie)
app.use((req, res, next) => {
  const origSetHeader = res.setHeader.bind(res);
  const origGetHeader = res.getHeader ? res.getHeader.bind(res) : () => undefined;
  const origAppend = typeof res.append === 'function' ? res.append.bind(res) : null;
  const origCookie = typeof res.cookie === 'function' ? res.cookie.bind(res) : null;

  const ensurePriorityArray = (value) => {
    const arr = Array.isArray(value) ? value.slice() : (value === undefined || value === null ? [] : [String(value)]);
    return arr.map((s) => {
      const str = String(s);
      // If Priority already present (case-insensitive), leave as-is
      if (/priority=/i.test(str)) return str;
      // Otherwise append Priority=High
      return `${str}; Priority=High`;
    });
  };

  res.setHeader = (name, value) => {
    if (String(name).toLowerCase() === 'set-cookie') {
      const withPriority = ensurePriorityArray(value);
      return origSetHeader('Set-Cookie', withPriority);
    }
    return origSetHeader(name, value);
  };

  if (origAppend) {
    res.append = (name, value) => {
      if (String(name).toLowerCase() === 'set-cookie') {
        const existing = origGetHeader('Set-Cookie');
        const existingArr = Array.isArray(existing) ? existing.slice() : (existing ? [existing] : []);
        const toAppend = Array.isArray(value) ? value : [value];
        const merged = existingArr.concat(toAppend);
        return origSetHeader('Set-Cookie', ensurePriorityArray(merged));
      }
      return origAppend(name, value);
    };
  }

  if (origCookie) {
    // wrap res.cookie so options-based cookie writes also get Priority enforced
    res.cookie = (name, val, options = {}) => {
      // call original to allow Express to build header
      const resVal = origCookie(name, val, options);
      // read header and ensure priority
      try {
        const sc = origGetHeader('Set-Cookie');
        if (sc) origSetHeader('Set-Cookie', ensurePriorityArray(sc));
      } catch (e) {
        // ignore
      }
      return resVal;
    };
  }

  next();
});

// Parse JSON early so routes can access req.body reliably
app.use(express.json());

// Simple request logger for debugging incoming requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
  next();
});

// Health-check endpoint
app.get('/health', (_req, res) => res.json({ ok: true }));

// Debug helper: quick endpoint to verify server is reachable
app.get('/api/debug/bluesky', (req, res) => {
  console.log('DEBUG /api/debug/bluesky called from', req.ip || req.headers['x-forwarded-for']);
  res.json({ ok: true, message: 'debug endpoint reached', time: Date.now() });
});

// Dev-only: return selected environment variables to help debug OAuth config
app.get('/api/debug/env', (req, res) => {
  try {
    if (process.env.NODE_ENV === 'production') return res.status(404).json({ error: 'Not available in production' });
    return res.json({
      GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || null,
      GOOGLE_REDIRECT_URI: process.env.GOOGLE_REDIRECT_URI || null,
      VITE_AUTH_GOOGLE: process.env.VITE_AUTH_GOOGLE || null,
      CLIENT_URL: process.env.CLIENT_URL || null,
    });
  } catch (e) {
    console.error('Error in /api/debug/env', e);
    return res.status(500).json({ error: String(e) });
  }
});

// Safe /api/cars handler
app.get('/api/cars', (req, res) => {
  try {
    const cars = [
      { id: '1', make: 'Toyota', model: 'Camry', year: 2020 },
      { id: '2', make: 'Honda', model: 'Accord', year: 2021 },
      { id: '3', make: 'Ford', model: 'Mustang', year: 2022 }
    ];
    res.json({ cars });
  } catch (err) {
    console.error('GET /api/cars fallback error:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Allowed origins for CORS
const allowedOrigins = [
  process.env.CLIENT_URL || "http://localhost:7024",
  "https://apigetways-one.vercel.app",
];

// Ensure common dev frontend port is allowed if not explicitly set
const devClient = process.env.DEV_CLIENT_URL || 'http://localhost:9234';
if (!allowedOrigins.includes(devClient)) allowedOrigins.push(devClient);

// ✅ Secure CORS Configuration
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true, // Allow cookies and credentials
  })
);

// ✅ Security Middleware
app.use(helmet()); // Secure HTTP headers
app.use(hpp()); // Prevent HTTP Parameter Pollution

// Example: sanitize route
app.post('/sanitize', (req, res) => {
  const dirtyInput = req.body.content || '';
  const cleanInput = sanitizeHtml(dirtyInput, {
    allowedTags: [],
    allowedAttributes: {}
  });
  res.json({ sanitized: cleanInput });
});

app.use(cookieParser()); // Enable reading/writing cookies
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded requests

// Add middleware to parse ACCOUNT_CHOOSER from cookies or headers
app.use((req, res, next) => {
  try {
    const token = req.cookies["Love_wins_Whats_up_with_that"] || req.headers.authorization?.split(" ")[1];
    if (token) {
      req.headers.authorization = `Bearer ${token}`;
    }
  } catch (e) { /* ignore */ }
  next();
});

// Middleware to parse raw body for Stripe Webhooks (keep this route-specific)
app.use(
  "/webhook",
  bodyParser.raw({ type: "application/json" })
);

// ✅ API Routes (keep user/auth routes)
app.use('/api/users', userRoutes);
app.use('/api/auth', authRoutes);

// Protected example route (applies keys middleware)
app.use('/api/protected', keysMiddleware, (req, res) => {
  res.json({ ok: true, message: 'Protected area' });
});

// Ensure JSON parser for other routes if needed (already applied above)

// Stripe Webhook Endpoint (uses raw body)
app.post("/webhook", (req, res) => {
  const sig = req.headers["stripe-signature"];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    console.log("✅ Webhook verified:", event.type);
    // Basic handling
    switch (event.type) {
      case "payment_intent.succeeded":
        console.log("✅ PaymentIntent was successful!");
        break;
      default:
        console.log(`Unhandled event type ${event.type}`);
    }
    res.status(200).send("Received");
  } catch (err) {
    console.error("Webhook signature verification failed:", err && err.message ? err.message : err);
    res.status(400).send(`Webhook Error: ${err && err.message ? err.message : 'Invalid signature'}`);
  }
});

// Apply JSON parser for non-webhook routes if needed (already applied earlier)
app.use(bodyParser.json());

// Single Global Error Handler
app.use((err, req, res, next) => {
  console.error('🚨 Unhandled error:', err && err.stack ? err.stack : err);
  if (res.headersSent) return next(err);
  if (process.env.NODE_ENV !== 'production') {
    return res.status(500).json({ error: err?.message || 'Something went wrong', stack: err?.stack });
  }
  return res.status(500).json({ error: 'Something went wrong!' });
});

// Delegate logout handling to the centralized controller implementation
// (mounted via /api/auth routes as well). This avoids duplicate fragile
// implementations and ensures a single code-path for cookie clearing.
app.post('/api/auth/logout', (req, res, next) => {
  try {
    return authController.logout(req, res, next);
  } catch (err) {
    // Defensive: ensure any synchronous error here is handled
    console.error('Inline logout delegation failed:', err && err.stack ? err.stack : err);
    return res.status(500).json({ error: 'Logout failed' });
  }
});

// --- Socket.IO server (separate port) ---
const SOCKET_PORT = process.env.SOCKET_PORT || 2024;
try {
  const socketHttp = http.createServer();
  const io = new IOServer(socketHttp, {
    cors: {
      origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        if (process.env.NODE_ENV !== 'production') return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
      },
      methods: ["GET", "POST"],
      credentials: true,
    },
  });

  io.on('connection', (socket) => {
    console.log('⚡ Socket connected:', socket.id);

    socket.on('newUser', (data) => {
      try {
        const userId = data?.userId;
        console.log('newUser event:', userId);
        if (userId) socket.join(`user_${userId}`);
      } catch (e) { console.error(e); }
    });

    socket.on('disconnect', (reason) => {
      console.log('Socket disconnected', socket.id, reason);
    });
  });

  // Prevent unhandled 'error' events from crashing the process (e.g. EADDRINUSE)
  socketHttp.on('error', (err) => {
    console.error('Socket.HTTP server error (socket port may be in use):', err && err.message ? err.message : err);
  });

  socketHttp.listen(SOCKET_PORT, () => console.log(`Socket.IO server listening on port ${SOCKET_PORT}`));
} catch (err) {
  console.error('Failed to start Socket.IO server:', err);
}

// ✅ Start Server
const PORT = process.env.PORT || 2525;
app.listen(PORT, "0.0.0.0", () => console.log(`                                                                         
                                                                         
                                                                         
                                                                         
                                                                         
  ██████ ▓█████  ██▀███   ██▒   █▓▓█████  ██▀███      ▒█████   ███▄    █ 
▒██    ▒ ▓█   ▀ ▓██ ▒ ██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒   ▒██▒  ██▒ ██ ▀█   █ 
░ ▓██▄   ▒███   ▓██ ░▄█ ▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒   ▒██░  ██▒▓██  ▀█ ██▒https://patorjk.com/software/taag/#p=display&f=Bloody&t=%0ASERVER%20ON
  ▒   ██▒▒▓█  ▄ ▒██▀▀█▄    ▒██ █░░▒▓█  ▄ ▒██▀▀█▄     ▒██   ██░▓██▒  ▐▌██▒
▒██████▒▒░▒████▒░██▓ ▒██▒   ▒▀█░  ░▒████▒░██▓ ▒██▒   ░ ████▓▒░▒██░   ▓██░
▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒▓ ░▒▓░   ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░   ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
░ ░▒  ░ ░ ░ ░  ░  ░▒ ░ ▒░   ░ ░░   ░ ░  ░  ░▒ ░ ▒░     ░ ▒ ▒░ ░ ░░   ░ ▒░
░  ░  ░     ░     ░░   ░      ░░     ░     ░░   ░    ░ ░ ░ ▒     ░   ░ ░ 
      ░     ░  ░   ░           ░     ░  ░   ░            ░ ░           ░ 
                                          ${PORT}`));

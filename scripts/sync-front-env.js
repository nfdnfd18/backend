import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

// Load backend .env explicitly (avoids path issues when run from different cwd)
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

const out = [];
if (process.env.VITE_API_URL) out.push(`VITE_API_URL=${process.env.VITE_API_URL}`);
if (process.env.VITE_SOCKET_URL) out.push(`VITE_SOCKET_URL=${process.env.VITE_SOCKET_URL}`);
if (process.env.VITE_SECRET_KEY) out.push(`VITE_SECRET_KEY=${process.env.VITE_SECRET_KEY}`);

// Add Cloudinary variables if present
if (process.env.VITE_CLOUDINARY_CLOUD_NAME) out.push(`VITE_CLOUDINARY_CLOUD_NAME=${process.env.VITE_CLOUDINARY_CLOUD_NAME}`);
if (process.env.VITE_CLOUDINARY_UPLOAD_PRESET) out.push(`VITE_CLOUDINARY_UPLOAD_PRESET=${process.env.VITE_CLOUDINARY_UPLOAD_PRESET}`);
// Add social auth start URLs so frontend buttons can point at backend start endpoints
if (process.env.VITE_AUTH_GOOGLE) out.push(`VITE_AUTH_GOOGLE=${process.env.VITE_AUTH_GOOGLE}`);
if (process.env.VITE_AUTH_BSKY) out.push(`VITE_AUTH_BSKY=${process.env.VITE_AUTH_BSKY}`);

const dest = path.resolve(process.cwd(), '..', 'frontend', '.env');
fs.writeFileSync(dest, out.join('\n'));
console.log('Wrote frontend .env with', out.length, 'entries to', dest);

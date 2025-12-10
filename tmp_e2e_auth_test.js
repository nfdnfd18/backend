import fetch from 'node-fetch';

async function run() {
  const base = 'http://127.0.0.1:2525';
  const reg = await fetch(`${base}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier: 'e2e_try_1756144419402@test.local', password: 'TestPass123!' }),
  });
  console.log('register status', reg.status);
  console.log('register headers', Object.fromEntries(reg.headers.entries()));
  console.log('register body', await reg.json().catch(() => null));

  const login = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier: 'e2e_try_1756144419402@test.local', password: 'TestPass123!' }),
  });
  console.log('login status', login.status);
  console.log('login headers', Object.fromEntries(login.headers.entries()));
  console.log('login body', await login.json().catch(() => null));
}

run().catch((e)=>{ console.error(e); process.exit(1); });

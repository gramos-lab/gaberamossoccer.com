// Cloudflare Pages Function — POST https://gaberamossoccer.com/api/order-webhook
// Payhip webhook ("paid" and "refunded" events) for gaberamossoccer.com.
// Verifies the payload signature (sha256 of the Payhip API key) and appends a row to the orders Google Sheet.
//
// Secrets (Pages project → Settings → Variables and Secrets, Production):
//   PAYHIP_API_KEY     – Payhip Settings → Developer → "Your API Key". Used only to verify webhook signatures.
//   SHEET_WEBHOOK_URL  – Google Apps Script web-app URL that appends a row (see functions/sheet.gs)

export async function onRequestGet() {
  return new Response('ok', { status: 200 });
}

export async function onRequestPost({ request, env }) {
  const raw = await request.text();
  let body;
  try { body = JSON.parse(raw); } catch { return new Response('bad json', { status: 400 }); }

  const verified = await verify(body.signature, env.PAYHIP_API_KEY);
  if (env.PAYHIP_API_KEY && !verified) return new Response('invalid signature', { status: 401 });

  const type = body.type || '';
  if (type !== 'paid' && type !== 'refunded') return new Response('ignored', { status: 200 });

  const items = Array.isArray(body.items) ? body.items : [];
  const cents = Number(body.price || 0);
  const total = (cents / 100).toLocaleString('en-US', { style: 'currency', currency: body.currency || 'USD' });
  const when = new Date((body.date || body.date_created || Date.now() / 1000) * 1000).toISOString();
  const name = [body.customer_first_name, body.customer_last_name].filter(Boolean).join(' ');
  const meta = body.metadata || {};
  const order = {
    date: when,
    number: body.id || '',
    name,
    email: body.email || '',
    product: items.map(i => i.product_name).filter(Boolean).join(' + '),
    total,
    status: type === 'refunded' ? 'refunded' : 'paid',
    source: meta.source || '',
    receipt: items[0]?.product_permalink || '',
    mode: verified ? 'live' : 'unverified',
  };

  const results = {};
  if (env.SHEET_WEBHOOK_URL) {
    results.sheet = await appendSheet(order, env).catch(e => 'error: ' + e.message);
  }
  return Response.json({ ok: true, order: order.number, results });
}

async function verify(sigHex, apiKey) {
  if (!sigHex || !apiKey) return false;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(apiKey)));
  const expected = [...digest].map(b => b.toString(16).padStart(2, '0')).join('');
  if (expected.length !== sigHex.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ sigHex.charCodeAt(i);
  return diff === 0;
}

async function appendSheet(o, env) {
  const r = await fetch(env.SHEET_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ row: [o.date, o.number, o.name, o.email, o.product, o.total, o.status, o.source, o.receipt, o.mode] }),
    redirect: 'follow',
  });
  return r.ok ? 'appended' : 'failed: ' + r.status;
}

// Cloudflare Pages Function — POST https://gaberamossoccer.com/api/order-webhook
// Lemon Squeezy order_created webhook for gaberamossoccer.com
// Verifies the X-Signature HMAC, emails Gabe via Web3Forms, and (optionally) appends a row to a Google Sheet.
//
// Secrets (Pages project → Settings → Variables and Secrets, Production):
//   LS_WEBHOOK_SECRET   – the signing secret entered when creating the webhook in Lemon Squeezy
//   WEB3FORMS_KEY       – Web3Forms access key (same one the site's contact form uses)
//   SHEET_WEBHOOK_URL   – optional: Google Apps Script web-app URL that appends a row (see sheet.gs)
//   QUO_API_KEY         – optional: Quo (OpenPhone) API key → sends an SMS on each order
//   QUO_FROM            – optional: your Quo number in E.164 (+1516…) or its phone-number ID
//   QUO_TO              – optional: the cell to text, E.164

export async function onRequestGet() {
  return new Response('ok', { status: 200 });
}

export async function onRequestPost({ request, env }) {
  return handle(request, env);
}

async function handle(request, env) {
  {

    const raw = await request.text();
    const sig = request.headers.get('x-signature') || '';
    if (!(await verify(raw, sig, env.LS_WEBHOOK_SECRET))) {
      return new Response('invalid signature', { status: 401 });
    }

    let body;
    try { body = JSON.parse(raw); } catch { return new Response('bad json', { status: 400 }); }

    const event = body?.meta?.event_name;
    if (event !== 'order_created') return new Response('ignored', { status: 200 });

    const a = body.data?.attributes || {};
    const item = a.first_order_item || {};
    const custom = body.meta?.custom_data || {};
    const order = {
      date: a.created_at || new Date().toISOString(),
      number: a.order_number,
      id: body.data?.id,
      name: a.user_name || '',
      email: a.user_email || '',
      product: item.product_name || '',
      variant: item.variant_name || '',
      total: a.total_formatted || '',
      status: a.status_formatted || a.status || '',
      source: custom.source || '',
      receipt: a.urls?.receipt || '',
      test: !!a.test_mode,
    };

    const results = {};
    results.email = await notifyEmail(order, env).catch(e => 'error: ' + e.message);
    if (env.SHEET_WEBHOOK_URL) {
      results.sheet = await appendSheet(order, env).catch(e => 'error: ' + e.message);
    }
    if (env.QUO_API_KEY && env.QUO_FROM && env.QUO_TO) {
      results.text = await notifyText(order, env).catch(e => 'error: ' + e.message);
    }
    return Response.json({ ok: true, order: order.number, results });
  }
}

async function verify(raw, sigHex, secret) {
  if (!secret || !sigHex) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(raw)));
  const expected = [...mac].map(b => b.toString(16).padStart(2, '0')).join('');
  if (expected.length !== sigHex.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ sigHex.charCodeAt(i);
  return diff === 0;
}

async function notifyEmail(o, env) {
  const subject = `${o.test ? '[TEST] ' : ''}New order #${o.number} — ${o.total} — ${o.name || o.email}`;
  const message = [
    `New curriculum order on gaberamossoccer.com`,
    ``,
    `Order:    #${o.number} (${o.status})${o.test ? '  [TEST MODE]' : ''}`,
    `Product:  ${o.product}${o.variant && o.variant !== 'Default' ? ' — ' + o.variant : ''}`,
    `Total:    ${o.total}`,
    `Buyer:    ${o.name} <${o.email}>`,
    `Source:   ${o.source || '—'}`,
    `When:     ${o.date}`,
    ``,
    `Receipt:  ${o.receipt}`,
    `Orders:   https://app.lemonsqueezy.com/orders`,
  ].join('\n');
  const r = await fetch('https://api.web3forms.com/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ access_key: env.WEB3FORMS_KEY, subject, from_name: 'Gabe Ramos Soccer Store', replyto: o.email || undefined, message }),
  });
  const j = await r.json().catch(() => ({}));
  return j.success ? 'sent' : 'failed: ' + (j.message || r.status);
}

async function appendSheet(o, env) {
  const r = await fetch(env.SHEET_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ row: [o.date, o.number, o.name, o.email, o.product, o.total, o.status, o.source, o.receipt, o.test ? 'test' : 'live'] }),
    redirect: 'follow',
  });
  return r.ok ? 'appended' : 'failed: ' + r.status;
}

async function notifyText(o, env) {
  // Quo (formerly OpenPhone) Messages API: https://www.openphone.com/docs/api-reference/messages/send-a-text-message
  const content = `${o.test ? '[TEST] ' : ''}New order #${o.number}: ${o.total} — ${o.name || o.email} — ${o.product}`;
  const r = await fetch('https://api.openphone.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: env.QUO_API_KEY },
    body: JSON.stringify({ from: env.QUO_FROM, to: [env.QUO_TO], content }),
  });
  return r.ok ? 'sent' : 'failed: ' + r.status + ' ' + (await r.text()).slice(0, 120);
}

// Link decoder helper: a small Cloudflare Worker.
//
// What it does: fetches a web page for the decoder page and returns what the
// server sent back (redirect chain, final address, page text). It exists
// because browsers do not let one website read another.
//
// What it does not do: run JavaScript, solve captchas, fake clicks or
// timers, or hide who it is. It identifies itself honestly, so sites that
// refuse automated requests will refuse it too.
//
// Security: it only answers requests that send your ACCESS_KEY, so strangers
// who find the address cannot use it as a free proxy.
// Setup steps are in SETUP.md.

const MAX_HOPS = 6;
const MAX_BYTES = 1500000;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'X-Access-Key',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Max-Age': '86400',
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// Compare two strings without leaking where they differ.
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Only public web addresses are allowed, including at every redirect hop.
function checkUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch (e) {
    throw new Error('That is not a valid web address.');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error('Only http and https addresses are allowed.');
  }
  const h = u.hostname.toLowerCase();
  const privateV4 = /^(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
  if (
    h === 'localhost' ||
    h.endsWith('.local') ||
    h.endsWith('.internal') ||
    h.startsWith('[') ||
    privateV4.test(h)
  ) {
    throw new Error('That address is not allowed.');
  }
  return u;
}

async function readLimited(res) {
  const reader = res.body ? res.body.getReader() : null;
  if (!reader) return { text: '', truncated: false };
  const chunks = [];
  let total = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BYTES) {
      chunks.push(value.slice(0, value.length - (total - MAX_BYTES)));
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.length;
  }
  return { text: new TextDecoder('utf-8').decode(all), truncated };
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (request.method !== 'GET') return json({ error: 'Use GET.' }, 405);

    if (!env.ACCESS_KEY) return json({ error: 'ACCESS_KEY is not set on the Worker yet.' }, 500);
    const given = request.headers.get('X-Access-Key') || '';
    if (!safeEqual(given, String(env.ACCESS_KEY))) {
      return json({ error: 'Wrong or missing access key.' }, 401);
    }

    const target = new URL(request.url).searchParams.get('url');
    if (!target) return json({ error: 'Missing url parameter.' }, 400);

    try {
      let current = checkUrl(target).href;
      const chain = [];
      for (let hop = 0; hop <= MAX_HOPS; hop++) {
        const res = await fetch(current, {
          redirect: 'manual',
          headers: {
            'User-Agent': 'LinkDecoderHelper/1.0',
            Accept: 'text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5',
          },
        });
        const loc = res.headers.get('Location');
        if (res.status >= 300 && res.status < 400 && loc) {
          chain.push({ url: current, status: res.status });
          current = checkUrl(new URL(loc, current).href).href;
          continue;
        }
        const type = res.headers.get('Content-Type') || '';
        let body = '';
        let truncated = false;
        if (!type || /text|html|json|xml/i.test(type)) {
          const r = await readLimited(res);
          body = r.text;
          truncated = r.truncated;
        }
        return json({
          ok: true,
          url: target,
          finalUrl: current,
          status: res.status,
          chain,
          contentType: type,
          body,
          truncated,
        });
      }
      return json({ error: 'Too many redirects.' }, 508);
    } catch (e) {
      return json({ error: e && e.message ? e.message : 'Fetch failed.' }, 502);
    }
  },
};

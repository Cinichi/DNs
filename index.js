// 🛡️ SAFE + FAST DNS WORKER
// No complex "racing" logic that can crash.
// Uses "stale-while-revalidate" to make your phone feel instant.

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. DoH Endpoint
    if (url.pathname === '/dns-query') {
      return handleDoH(request);
    }

    // 2. JSON Endpoint
    if (url.pathname === '/resolve') {
      return handleJSON(request);
    }

    return getInterface(request);
  }
};

async function handleDoH(request) {
  let dnsQuery;

  // 1. Safety Check: Is the request valid?
  try {
    if (request.method === 'GET') {
      const dns = new URL(request.url).searchParams.get('dns');
      if (!dns) return new Response('Missing param', { status: 400 });
      dnsQuery = base64UrlDecode(dns);
    } else {
      dnsQuery = await request.arrayBuffer();
    }
  } catch (e) {
    return new Response('Bad Request', { status: 400 });
  }

  // 2. Define the "Turbo" Headers
  // These headers tell your phone: "Keep this DNS answer for 5 minutes.
  // If I ask again, give me the old answer INSTANTLY (0ms) while checking for new ones."
  const speedHeaders = {
    'Content-Type': 'application/dns-message',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'public, max-age=300, stale-while-revalidate=60' 
  };

  // 3. Try Cloudflare (Primary)
  try {
    const response = await fetch('https://1.1.1.1/dns-query', {
      method: 'POST',
      headers: { 'Accept': 'application/dns-message', 'Content-Type': 'application/dns-message' },
      body: dnsQuery
    });

    if (response.ok) {
      return new Response(response.body, { status: 200, headers: speedHeaders });
    }
  } catch (e) {
    // Silent fail -> move to fallback
  }

  // 4. Fallback to Google (If Cloudflare breaks)
  try {
    const fallback = await fetch('https://8.8.8.8/dns-query', {
      method: 'POST',
      headers: { 'Accept': 'application/dns-message', 'Content-Type': 'application/dns-message' },
      body: dnsQuery
    });

    return new Response(fallback.body, { status: fallback.status, headers: speedHeaders });
  } catch (e) {
    return new Response('DNS Error', { status: 502 });
  }
}

async function handleJSON(request) {
  const url = new URL(request.url);
  const name = url.searchParams.get('name');
  if(!name) return new Response('{}', {headers:{'Content-Type':'application/json'}});

  // Simple, direct fetch. No fancy logic to break things.
  const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${name}&type=A&ct=application/dns-json`, {
    headers: { 'Accept': 'application/dns-json' }
  });

  const newRes = new Response(res.body, res);
  newRes.headers.set('Cache-Control', 'public, max-age=300');
  return newRes;
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function getInterface(request) {
  const origin = new URL(request.url).origin;
  return new Response(`<!DOCTYPE html><html><body style="background:#111;color:#fff;font-family:sans-serif;padding:20px">
  <h3>🟢 Safe + Fast Worker Active</h3>
  <p>Endpoint: ${origin}/dns-query</p>
  </body></html>`, {headers:{'Content-Type':'text/html'}});
  }

// ⚡ ULTRA-FAST DNS WORKER (Stable Version)
// 🛡️ Fixes "Site Not Opening" by safely handling Cache permissions

const UPSTREAMS = [
  'https://1.1.1.1/dns-query',
  'https://8.8.8.8/dns-query',
  'https://9.9.9.9/dns-query',
];

const L1_CACHE_SIZE = 500;
const l1Cache = new Map();

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      // CORS Preflight
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Max-Age': '86400',
          }
        });
      }

      // Router
      switch (url.pathname) {
        case '/dns-query':
          return await handleDoH(request, ctx);
        case '/resolve':
          return await handleJSON(request, ctx);
        case '/':
          return getInterface(request);
        default:
          return new Response('404 Not Found', { status: 404 });
      }
    } catch (err) {
      // 🚑 Global Error Handler - Prevents "Site Not Opening"
      return new Response(`Critical Error: ${err.message}\n${err.stack}`, { 
        status: 500, 
        headers: { 'Content-Type': 'text/plain' } 
      });
    }
  }
};

// ============================================================================
// 🧬 SAFE DNS HANDLER
// ============================================================================

async function handleDoH(request, ctx) {
  let dnsQuery;

  try {
    if (request.method === 'GET') {
      const dnsParam = new URL(request.url).searchParams.get('dns');
      if (!dnsParam) throw new Error('Missing param');
      dnsQuery = base64UrlDecode(dnsParam);
    } else if (request.method === 'POST') {
      dnsQuery = await request.arrayBuffer();
    } else {
      return new Response('Method Not Allowed', { status: 405 });
    }
  } catch (e) {
    return new Response('Bad Request', { status: 400 });
  }

  const cacheKeyStr = await bufferToHex(dnsQuery);
  const cacheUrl = new URL(`https://dns-cache.local/${cacheKeyStr}`);
  const cacheReq = new Request(cacheUrl, { method: 'GET' });

  // 1. Check Memory Cache (Always Safe)
  const l1Hit = l1Cache.get(cacheKeyStr);
  if (l1Hit && l1Hit.expiry > Date.now()) {
    return new Response(l1Hit.data, {
      headers: { ...l1Hit.headers, 'X-Cache': 'L1-MEMORY' }
    });
  }

  // 2. Check Cloudflare Cache (Safe Mode)
  let cache = null;
  try {
    // This line crashes on workers.dev if not wrapped in try/catch
    cache = caches.default;
    const l2Hit = await cache.match(cacheReq);
    if (l2Hit) {
      const data = await l2Hit.clone().arrayBuffer();
      addToL1(cacheKeyStr, data, l2Hit.headers);
      const response = new Response(data, l2Hit);
      response.headers.set('X-Cache', 'L2-EDGE');
      return response;
    }
  } catch (e) {
    // Caching unavailable, ignore and proceed
  }

  // 3. Race Upstreams
  const raceInit = {
    method: 'POST',
    headers: {
      'Accept': 'application/dns-message',
      'Content-Type': 'application/dns-message'
    },
    body: dnsQuery,
    cf: { cacheTtl: 300, cacheEverything: true }
  };

  try {
    const fastestResponse = await Promise.any(
      UPSTREAMS.map(endpoint => fetch(endpoint, raceInit))
    );

    if (!fastestResponse.ok) throw new Error('Upstream Failed');

    const responseBody = await fastestResponse.arrayBuffer();
    
    const responseHeaders = new Headers(fastestResponse.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Cache-Control', 'public, max-age=300');
    responseHeaders.set('Content-Type', 'application/dns-message');
    responseHeaders.set('X-Cache', 'MISS-RACE-WINNER');

    const finalResponse = new Response(responseBody, {
      status: 200,
      headers: responseHeaders
    });

    // Update Caches safely
    ctx.waitUntil((async () => {
      if (cache) {
        try { await cache.put(cacheReq, finalResponse.clone()); } catch(e){}
      }
      addToL1(cacheKeyStr, responseBody, responseHeaders);
    })());

    return finalResponse;

  } catch (error) {
    return new Response('DNS Resolution Failed', { status: 502 });
  }
}

// ============================================================================
// 📝 SAFE JSON HANDLER
// ============================================================================

async function handleJSON(request, ctx) {
  const url = new URL(request.url);
  const name = url.searchParams.get('name');
  const type = url.searchParams.get('type') || 'A';
  
  if(!name) return new Response(JSON.stringify({error: 'Missing name'}), { 
    status: 400, headers: {'Content-Type': 'application/json'} 
  });

  const upstream = `https://cloudflare-dns.com/dns-query?name=${name}&type=${type}&ct=application/dns-json`;
  
  try {
    const response = await fetch(upstream, {
      headers: { 'Accept': 'application/dns-json' }
    });
    
    const data = await response.json();
    data.Provider = "Cloudflare-Worker-Pro";
    
    return new Response(JSON.stringify(data), {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=300'
      }
    });
  } catch (e) {
    return new Response(JSON.stringify({error: e.message}), { status: 500 });
  }
}

// ============================================================================
// 🛠️ UTILITIES
// ============================================================================

function addToL1(key, data, headers) {
  if (l1Cache.size >= L1_CACHE_SIZE) {
    const firstKey = l1Cache.keys().next().value;
    l1Cache.delete(firstKey);
  }
  const headerObj = {};
  headers.forEach((v, k) => headerObj[k] = v);
  l1Cache.set(key, { data, headers: headerObj, expiry: Date.now() + 300000 });
}

async function bufferToHex(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// ============================================================================
// 🖥️ UI
// ============================================================================

function getInterface(request) {
  const origin = new URL(request.url).origin;
  return new Response(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>⚡ Safe DNS Worker</title>
  <style>
    :root { --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --accent: #3b82f6; }
    body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .container { width: 100%; max-width: 600px; padding: 20px; }
    .card { background: var(--card); padding: 30px; border-radius: 16px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); border: 1px solid #334155; }
    h1 { margin: 0 0 10px 0; color: #60a5fa; font-size: 2.5rem; }
    .endpoint { background: #020617; padding: 15px; border-radius: 8px; font-family: monospace; color: #a5b4fc; margin: 20px 0; word-break: break-all; border: 1px solid #334155; }
    button { background: var(--accent); color: white; border: none; padding: 12px 24px; border-radius: 8px; font-weight: bold; cursor: pointer; width: 100%; margin-top: 10px; }
    #output { margin-top: 20px; white-space: pre-wrap; font-family: monospace; color: #86efac; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>DNS Racer</h1>
      <p>Status: 🟢 Online & Stable</p>
      <div class="endpoint">${origin}/dns-query</div>
      <button onclick="testDNS('${origin}')">⚡ Test Latency</button>
      <div id="output"></div>
    </div>
  </div>
  <script>
    async function testDNS(origin) {
      const out = document.getElementById('output');
      out.innerHTML = 'Testing...';
      try {
        const start = performance.now();
        const res = await fetch(origin + '/resolve?name=google.com');
        const data = await res.json();
        const total = (performance.now() - start).toFixed(1);
        out.innerHTML = \`Result: \${total}ms\\nProvider: \${data.Provider}\`;
      } catch(e) { out.innerHTML = 'Error: ' + e.message; }
    }
  </script>
</body>
</html>`, { headers: { 'Content-Type': 'text/html' }});
    }

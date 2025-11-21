// ⚡ ULTRA-FAST DNS WORKER (Multi-Tier Cache + Parallel Racing)
// 🚀 Strategy: Race Cloudflare, Google, and Quad9 simultaneously. First one wins.

// 🌐 Configuration
const UPSTREAMS = [
  'https://1.1.1.1/dns-query',      // Cloudflare (Usually fastest)
  'https://8.8.8.8/dns-query',      // Google (Reliable fallback)
  'https://9.9.9.9/dns-query',      // Quad9 (Security focused)
];

// 🧠 L1 Cache: In-Memory (Microseconds, local to isolate)
const L1_CACHE_SIZE = 500;
const l1Cache = new Map();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Handle CORS Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, HEAD, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '86400',
        }
      });
    }

    // 🛣️ Router
    switch (url.pathname) {
      case '/dns-query':
        return handleDoH(request, ctx);
      case '/resolve':
        return handleJSON(request, ctx);
      case '/':
        return getInterface(request);
      default:
        return new Response('404 Not Found', { status: 404 });
    }
  }
};

// ============================================================================
// 🧬 CORE: DNS-OVER-HTTPS HANDLER (RFC 8484)
// ============================================================================

async function handleDoH(request, ctx) {
  let dnsQuery;

  // 1. Extract Query
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

  // 2. Generate Cache Key (Hash of the query buffer)
  // We use the raw buffer as key to avoid parsing cost for caching
  const cacheKeyStr = await bufferToHex(dnsQuery);
  const cacheUrl = new URL(`https://dns-cache.local/${cacheKeyStr}`);
  const cacheReq = new Request(cacheUrl, { method: 'GET' });

  // ⚡ Tier 1: Check In-Memory L1 Cache
  const l1Hit = l1Cache.get(cacheKeyStr);
  if (l1Hit && l1Hit.expiry > Date.now()) {
    return new Response(l1Hit.data, {
      headers: { ...l1Hit.headers, 'X-Cache': 'L1-MEMORY' }
    });
  }

  // ⚡ Tier 2: Check Cloudflare Edge Cache (L2)
  const cache = caches.default;
  const l2Hit = await cache.match(cacheReq);
  if (l2Hit) {
    // Promote to L1
    const data = await l2Hit.clone().arrayBuffer();
    addToL1(cacheKeyStr, data, l2Hit.headers);
    
    const response = new Response(data, l2Hit);
    response.headers.set('X-Cache', 'L2-EDGE');
    return response;
  }

  // 🏁 Tier 3: THE RACE (Parallel Fetch)
  // We explicitly set Accept headers to ensure binary DNS response
  const raceInit = {
    method: 'POST',
    headers: {
      'Accept': 'application/dns-message',
      'Content-Type': 'application/dns-message'
    },
    body: dnsQuery,
    cf: {
      cacheTtl: 300, // Tell Cloudflare internal logic to cache this fetch if possible
      cacheEverything: true
    }
  };

  try {
    // Promise.any resolves as soon as the FIRST promise fulfills
    const fastestResponse = await Promise.any(
      UPSTREAMS.map(endpoint => fetch(endpoint, raceInit))
    );

    if (!fastestResponse.ok) throw new Error('Upstream Failed');

    const responseBody = await fastestResponse.arrayBuffer();
    
    // Create Optimized Response
    const responseHeaders = new Headers(fastestResponse.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
    responseHeaders.set('Content-Type', 'application/dns-message');
    responseHeaders.set('X-Cache', 'MISS-RACE-WINNER');

    const finalResponse = new Response(responseBody, {
      status: 200,
      headers: responseHeaders
    });

    // 💾 Update Caches (Non-blocking)
    ctx.waitUntil((async () => {
      // Update L2
      await cache.put(cacheReq, finalResponse.clone());
      // Update L1
      addToL1(cacheKeyStr, responseBody, responseHeaders);
    })());

    return finalResponse;

  } catch (error) {
    return new Response('DNS Resolution Failed', { status: 502 });
  }
}

// ============================================================================
// 📝 JSON API HANDLER
// ============================================================================

async function handleJSON(request, ctx) {
  const url = new URL(request.url);
  const name = url.searchParams.get('name');
  const type = url.searchParams.get('type') || 'A';
  
  if(!name) return new Response('Missing name', { status: 400 });

  // Simple proxy to Cloudflare DoH JSON API (It's the most reliable for JSON)
  // We don't race JSON because formatting differs slightly between providers
  const upstream = `https://cloudflare-dns.com/dns-query?name=${name}&type=${type}&ct=application/dns-json`;
  
  const cache = caches.default;
  const cacheKey = new Request(upstream, request); // Use upstream URL as key
  
  // Check Cache
  const cached = await cache.match(cacheKey);
  if(cached) {
    const res = new Response(cached.body, cached);
    res.headers.set('X-Cache', 'HIT');
    res.headers.set('Access-Control-Allow-Origin', '*');
    return res;
  }

  const response = await fetch(upstream, {
    headers: { 'Accept': 'application/dns-json' }
  });

  const responseClone = response.clone();
  const data = await response.json();
  
  // Add timing info to JSON
  data.Provider = "Cloudflare-Worker-Pro";
  
  const finalRes = new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=300'
    }
  });

  ctx.waitUntil(cache.put(cacheKey, responseClone));
  
  return finalRes;
}

// ============================================================================
// 🛠️ UTILITIES & HELPERS
// ============================================================================

// Efficient L1 Cache Manager
function addToL1(key, data, headers) {
  if (l1Cache.size >= L1_CACHE_SIZE) {
    const firstKey = l1Cache.keys().next().value;
    l1Cache.delete(firstKey);
  }
  
  // Extract plain object headers for storage
  const headerObj = {};
  headers.forEach((v, k) => headerObj[k] = v);

  l1Cache.set(key, {
    data,
    headers: headerObj,
    expiry: Date.now() + 300000 // 5 minutes
  });
}

// Fast Hex conversion for cache keys
async function bufferToHex(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
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
// 🖥️ UI INTERFACE
// ============================================================================

function getInterface(request) {
  const origin = new URL(request.url).origin;
  return new Response(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>⚡ Ultra-Fast DNS Worker</title>
  <style>
    :root { --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --accent: #3b82f6; }
    body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .container { width: 100%; max-width: 600px; padding: 20px; }
    .card { background: var(--card); padding: 30px; border-radius: 16px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); border: 1px solid #334155; }
    h1 { margin: 0 0 10px 0; background: linear-gradient(to right, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 2.5rem; }
    .badge { background: #059669; color: white; padding: 4px 12px; border-radius: 99px; font-size: 0.8rem; font-weight: bold; vertical-align: middle; }
    .endpoint { background: #020617; padding: 15px; border-radius: 8px; font-family: monospace; color: #a5b4fc; margin: 20px 0; word-break: break-all; border: 1px solid #334155; position: relative; }
    button { background: var(--accent); color: white; border: none; padding: 12px 24px; border-radius: 8px; font-weight: bold; cursor: pointer; transition: transform 0.1s; width: 100%; }
    button:active { transform: scale(0.98); }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 20px; }
    .stat { background: rgba(255,255,255,0.05); padding: 15px; border-radius: 8px; text-align: center; }
    #output { margin-top: 20px; white-space: pre-wrap; font-family: monospace; font-size: 0.9rem; color: #86efac; display: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>DNS Racer <span class="badge">v2.0</span></h1>
      <p>Racing Cloudflare, Google & Quad9 for the lowest latency.</p>
      
      <div class="endpoint" onclick="navigator.clipboard.writeText(this.innerText);alert('Copied!')">
        ${origin}/dns-query
      </div>

      <div class="grid">
        <div class="stat"><strong>L1 Cache</strong><br>In-Memory</div>
        <div class="stat"><strong>L2 Cache</strong><br>Edge Network</div>
      </div>

      <div class="grid">
        <button onclick="testDNS('${origin}')">⚡ Test Latency</button>
        <button onclick="window.open('${origin}/resolve?name=google.com')">🔍 JSON API</button>
      </div>

      <div id="output"></div>
    </div>
  </div>
  <script>
    async function testDNS(origin) {
      const out = document.getElementById('output');
      out.style.display = 'block';
      out.innerHTML = 'Racing...';
      const start = performance.now();
      try {
        const res = await fetch(origin + '/resolve?name=cloudflare.com');
        const data = await res.json();
        const total = (performance.now() - start).toFixed(1);
        out.innerHTML = \`⏱️ Total Roundtrip: \${total}ms\\n📦 Provider: \${data.Provider}\\n🎯 Cache Status: \${res.headers.get('X-Cache')}\`;
      } catch(e) { out.innerHTML = 'Error: ' + e.message; }
    }
  </script>
</body>
</html>`, { headers: { 'Content-Type': 'text/html' }});
}



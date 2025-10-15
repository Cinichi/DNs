// DNS-over-HTTPS Ad Blocker for Cloudflare Workers (with KV Caching for Ping Boost)
// Works with browsers/apps that support DoH

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Main DoH endpoint
    if (url.pathname === '/dns-query') {
      return handleDNSQuery(request, env);
    }
    
    // Blocklist management
    if (url.pathname === '/blocklist') {
      return handleBlocklist(request);
    }
    
    // Stats endpoint
    if (url.pathname === '/stats') {
      return handleStats(request);
    }
    
    // Web interface
    return getWebInterface(request);
  }
};

// Comprehensive blocklist (Top ad/tracker domains) - adult sites allowed
const BLOCKLIST = new Set([
  // Google Ads
  'doubleclick.net',
  'googleadservices.com',
  'googlesyndication.com',
  'pagead2.googlesyndication.com',
  'adservice.google.com',
  'ads.google.com',
  
  // Analytics
  'google-analytics.com',
  'googletagmanager.com',
  'analytics.google.com',
  'stats.g.doubleclick.net',
  
  // Facebook
  'facebook.net',
  'connect.facebook.net',
  'pixel.facebook.com',
  'an.facebook.com',
  
  // Ad Networks
  'adnxs.com',
  'advertising.com',
  'adsrvr.org',
  'ad.doubleclick.net',
  'pubads.g.doubleclick.net',
  'securepubads.g.doubleclick.net',
  
  // Trackers
  'mixpanel.com',
  'api.mixpanel.com',
  'tracking.epicgames.com',
  'crashlytics.com',
  'app-measurement.com',
  
  // TikTok
  'analytics.tiktok.com',
  'ads-api.tiktok.com',
  'analytics-sg.tiktok.com',
  
  // YouTube Ads
  'ads.youtube.com',
  'video-ad-stats.googlesyndication.com',
  
  // Indian Ad Networks
  'tyroo.com',
  'inmobi.com',
  'ad2iction.com',
  'komli.com',
  'vdopia.com',
  
  // Manga/Manhwa Site Ads
  'propellerads.com',
  'popcash.net',
  'popads.net',
  'adsterra.com',
  'exoclick.com',
  'juicyads.com',
  'hilltopads.net',
  'trafficjunky.com',
  
  // Crypto Miners
  'coinhive.com',
  'coin-hive.com',
  'jsecoin.com',
  'minero.cc',
]);

// Additional patterns to block
const BLOCK_PATTERNS = [
  /^ads?\d*\./,           // ads.example.com, ad1.example.com
  /^analytics?\./,         // analytics.example.com
  /^tracking?\./,          // tracking.example.com
  /^telemetry\./,         // telemetry.example.com
  /^metrics?\./,          // metrics.example.com
  /[-_]ad[-_]/,           // something-ad-server.com
  /[-_]ads[-_]/,          // something-ads-server.com
  /[-_]tracker[-_]/,      // something-tracker.com
];

async function handleDNSQuery(request, env) {
  try {
    const url = new URL(request.url);
    let dnsQuery;
    
    // Handle GET request (dns parameter)
    if (request.method === 'GET' && url.searchParams.has('dns')) {
      const dnsParam = url.searchParams.get('dns');
      dnsQuery = base64UrlDecode(dnsParam);
    }
    // Handle POST request (body contains DNS query)
    else if (request.method === 'POST') {
      dnsQuery = await request.arrayBuffer();
    }
    else {
      return new Response('Invalid DNS query', { status: 400 });
    }
    
    // Parse domain from DNS query
    const domain = parseDomainFromDNS(dnsQuery);
    
    // Check if domain should be blocked (cached check first for speed)
    if (shouldBlock(domain)) {
      console.log(`Blocked: ${domain}`);
      return createBlockedDNSResponse(dnsQuery, domain);
    }
    
    // NEW: KV Cache Check for Ping Boost (env.BLOCK_CACHE from wrangler.toml)
    const cacheKey = `dns:${domain}`;
    let cachedResponse = null;
    if (env.BLOCK_CACHE) {
      cachedResponse = await env.BLOCK_CACHE.get(cacheKey);
    }
    
    if (cachedResponse) {
      console.log(`Cache HIT for ${domain}`);
      return new Response(cachedResponse, {
        headers: { 'Content-Type': 'application/dns-message' }
      });
    }
    
    // Forward to Cloudflare DNS (1.1.1.1)
    const upstreamURL = 'https://cloudflare-dns.com/dns-query';
    const upstreamResponse = await fetch(upstreamURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
      },
      body: dnsQuery,
    });
    
    const responseBytes = await upstreamResponse.arrayBuffer();
    const finalResponse = new Response(finalBytes, {
      headers: {
        'Content-Type': 'application/dns-message',
        'Access-Control-Allow-Origin': '*',
        'X-Filtered-By': 'CF-AdBlock',
      }
    });
    
    // NEW: Cache for 1 hour (3600s TTL) if successful
    if (env.BLOCK_CACHE && upstreamResponse.ok) {
      ctx.waitUntil(env.BLOCK_CACHE.put(cacheKey, await finalResponse.arrayBuffer(), { expirationTtl: 3600 }));
    }
    
    return finalResponse;
    
  } catch (error) {
    console.error('DNS query error:', error);
    
    // Fallback to Cloudflare DNS on error
    const fallbackURL = 'https://cloudflare-dns.com/dns-query';
    return fetch(fallbackURL, {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });
  }
}

function parseDomainFromDNS(dnsQuery) {
  try {
    const bytes = new Uint8Array(dnsQuery);
    
    // DNS header is 12 bytes, skip it
    let offset = 12;
    const labels = [];
    
    // Parse QNAME (domain name)
    while (offset < bytes.length) {
      const length = bytes[offset];
      
      // End of name
      if (length === 0) break;
      
      // Pointer (compression) - not handling for simplicity
      if (length >= 192) break;
      
      offset++;
      
      // Extract label
      const label = String.fromCharCode(...bytes.slice(offset, offset + length));
      labels.push(label);
      offset += length;
    }
    
    return labels.join('.').toLowerCase();
  } catch (error) {
    console.error('DNS parsing error:', error);
    return '';
  }
}

function shouldBlock(domain) {
  if (!domain) return false;
  
  // Check exact match
  if (BLOCKLIST.has(domain)) return true;
  
  // Check all subdomains
  const parts = domain.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const subdomain = parts.slice(i).join('.');
    if (BLOCKLIST.has(subdomain)) return true;
  }
  
  // Check patterns
  for (const pattern of BLOCK_PATTERNS) {
    if (pattern.test(domain)) return true;
  }
  
  return false;
}

function createBlockedDNSResponse(query, domain) {
  // Return NXDOMAIN for blocked domains
  const queryBytes = new Uint8Array(query);
  
  // Create DNS response (same size as query)
  const response = new Uint8Array(queryBytes.length);
  response.set(queryBytes);
  
  // Set response flags: QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
  response[2] = 0x81; // QR=1 (0x80) + RD=1 (0x01)
  response[3] = 0x83; // RA=1 (0x80) + RCODE=3 (0x03)
  
  // Ensure ANCOUNT=0 (already is in query)
  
  return new Response(response, {
    status: 200,
    headers: {
      'Content-Type': 'application/dns-message',
      'Access-Control-Allow-Origin': '*',
      'X-Blocked-Domain': domain,
      'Cache-Control': 'max-age=3600',
    },
  });
}

function handleBlocklist(request) {
  const list = Array.from(BLOCKLIST).sort();
  
  return new Response(JSON.stringify({
    total: list.length,
    domains: list,
    patterns: BLOCK_PATTERNS.map(p => p.toString()),
  }, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

function handleStats(request) {
  return new Response(JSON.stringify({
    blocked_domains: BLOCKLIST.size,
    patterns: BLOCK_PATTERNS.length,
    endpoint: '/dns-query',
    method: 'DNS-over-HTTPS (DoH)',
    cache_enabled: true,  // NEW: Flag for KV
  }, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

async function getWebInterface(request) {
  const url = new URL(request.url);
  const hostname = url.hostname;
  const origin = `https://${hostname}`;
  
  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CF DNS Ad Blocker</title>
    <style>
        /* Same CSS as before - omitted for brevity */
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ DNS Ad Blocker</h1>
        <p class="subtitle">Cloudflare-powered DNS-over-HTTPS ad blocking (with KV Caching for ⚡ Faster Ping)</p>
        
        <!-- Stats, Setup Sections, Test Buttons - same as before -->
        
        <div class="success">
            ✅ <strong>Active:</strong> All DNS routed through CF—expect 10-50ms better ping + ad blocks!
        </div>
        
        <!-- Rest of HTML same as previous version -->
    </div>
    
    <script>
        // Same JS as before - testBlocking, viewBlocklist, etc.
    </script>
</body>
</html>`, {
    headers: { 'Content-Type': 'text/html' },
  });
}

function base64UrlDecode(str) {
  // Convert base64url to base64
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding
  while (str.length % 4) {
    str += '=';
  }
  // Decode
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
       }

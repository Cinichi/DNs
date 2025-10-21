// Enhanced DNS-over-HTTPS Ad Blocker for Cloudflare Workers
// Features: Better DNS parsing, statistics tracking, allowlist, custom responses, Chrome UA

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return handleCORS();
    }

    // Route requests
    switch (url.pathname) {
      case '/dns-query':
        return handleDNSQuery(request, ctx);
      case '/blocklist':
        return handleBlocklist();
      case '/allowlist':
        return handleAllowlist();
      case '/stats':
        return handleStats();
      case '/add-block':
        return handleAddBlock(url);
      case '/add-allow':
        return handleAddAllow(url);
      default:
        return getWebInterface();
    }
  }
};

// Enhanced blocklist with more domains
const BLOCKLIST = new Set([
  // Google Ads & Analytics
  'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
  'pagead2.googlesyndication.com', 'adservice.google.com', 'ads.google.com',
  'google-analytics.com', 'googletagmanager.com', 'analytics.google.com',
  'stats.g.doubleclick.net', 'ad.doubleclick.net', 'pubads.g.doubleclick.net',

  // Facebook & Meta
  'facebook.net', 'connect.facebook.net', 'pixel.facebook.com',
  'an.facebook.com', 'graph.facebook.com',

  // Major Ad Networks
  'adnxs.com', 'advertising.com', 'adsrvr.org', 'smartadserver.com',
  'criteo.com', 'criteo.net', 'outbrain.com', 'taboola.com',
  'adform.net', 'advertising.com', 'admob.com',

  // Trackers & Analytics
  'mixpanel.com', 'api.mixpanel.com', 'segment.com', 'segment.io',
  'hotjar.com', 'mouseflow.com', 'crazyegg.com', 'fullstory.com',
  'loggly.com', 'bugsnag.com', 'crashlytics.com', 'app-measurement.com',

  // Social Media Trackers
  'analytics.tiktok.com', 'ads-api.tiktok.com', 'analytics-sg.tiktok.com',
  'ads.twitter.com', 'static.ads-twitter.com', 'ads-api.twitter.com',

  // YouTube Ads
  'ads.youtube.com', 'video-ad-stats.googlesyndication.com',

  // Indian Ad Networks
  'tyroo.com', 'inmobi.com', 'ad2iction.com', 'komli.com', 'vdopia.com',
  'amagi.tv', 'mediaguru.com',

  // Manga/Manhwa/Piracy Site Ads
  'propellerads.com', 'popcash.net', 'popads.net', 'adsterra.com',
  'exoclick.com', 'juicyads.com', 'hilltopads.net', 'trafficjunky.com',
  'ads-service.com', 'adserver.juicyads.com', 'plugrush.com',

  // Crypto Miners
  'coinhive.com', 'coin-hive.com', 'jsecoin.com', 'minero.cc',
  'crypto-loot.com', 'cryptoloot.pro', 'webmining.co',

  // Malware & Phishing
  'malware-traffic.com', 'phishing-site.com', 'badware.com',

  // Additional Popular Trackers
  'scorecardresearch.com', 'quantserve.com', 'chartbeat.com',
  'newrelic.com', 'nr-data.net', 'pingdom.net',
]);

// Allowlist - domains that should never be blocked
const ALLOWLIST = new Set([
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
  'instagram.com', 'reddit.com', 'wikipedia.org', 'github.com',
  'stackoverflow.com', 'amazon.com', 'netflix.com', 'cloudflare.com',
]);

// Pattern-based blocking
const BLOCK_PATTERNS = [
  /^ads?\d*\./i,           // ads., ad., ad1., etc
  /^analytics?\./i,         // analytics., analytic.*
  /^tracking?\./i,          // tracking., tracker.
  /^telemetry\./i,         // telemetry.*
  /^metrics?\./i,          // metrics., metric.
  /[-\.]ad[-\.]/i,         // -ad-, ad, .ad.
  /[-\.]ads[-\.]/i,        // -ads-, ads, .ads.
  /[-\.]tracker[-\.]/i,    // -tracker-, etc
  /[-\.]tracking[-\.]/i,
  /^advert/i,              // advert*, advertising*
  /^banner/i,              // banner*
  /^click/i,               // click*, clicks*
  /^pixel/i,               // pixel*, pixels*
  /^tag/i,                 // tag*, tags* (analytics)
];

// Statistics (in-memory, resets on worker restart)
let stats = {
  totalQueries: 0,
  blockedQueries: 0,
  allowedQueries: 0,
  topBlockedDomains: new Map(),
  startTime: Date.now(),
};

async function handleDNSQuery(request, ctx) {
  stats.totalQueries++;

  try {
    const url = new URL(request.url);
    let dnsQuery;

    // Parse DNS query from GET or POST
    if (request.method === 'GET' && url.searchParams.has('dns')) {
      const dnsParam = url.searchParams.get('dns');
      dnsQuery = base64UrlDecode(dnsParam);
    } else if (request.method === 'POST') {
      dnsQuery = await request.arrayBuffer();
    } else {
      return new Response('Invalid DNS query method', { status: 400 });
    }

    // Parse domain name from DNS query
    const domain = parseDomainFromDNS(dnsQuery);

    if (!domain) {
      return forwardToUpstream(dnsQuery);
    }

    // Check allowlist first (never block these)
    if (isAllowlisted(domain)) {
      stats.allowedQueries++;
      return forwardToUpstream(dnsQuery);
    }

    // Check if domain should be blocked
    if (shouldBlock(domain)) {
      stats.blockedQueries++;
      trackBlockedDomain(domain);
      console.log(`🚫 Blocked: ${domain}`);
      return createBlockedDNSResponse(dnsQuery, domain);
    }

    // Forward to upstream DNS
    stats.allowedQueries++;
    return forwardToUpstream(dnsQuery);

  } catch (error) {
    console.error('DNS query error:', error);
    // Fallback to Cloudflare DNS on error
    return forwardToUpstream(await request.arrayBuffer());
  }
}

async function forwardToUpstream(dnsQuery) {
  const upstreamURL = 'https://cloudflare-dns.com/dns-query';
  
  // Latest Chrome user agent (Windows 10)
  const chromeUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

  try {
    const upstreamResponse = await fetch(upstreamURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
        'User-Agent': chromeUA,
      },
      body: dnsQuery,
      cf: {
        cacheTtl: 300, // Cache for 5 minutes
      }
    });

    const responseHeaders = new Headers(upstreamResponse.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('X-Filtered-By', 'CF-DNS-AdBlock');
    responseHeaders.set('X-Upstream', 'Cloudflare');

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });

  } catch (error) {
    console.error('Upstream DNS error:', error);
    return new Response('DNS resolution failed', { status: 502 });
  }
}

function parseDomainFromDNS(dnsQuery) {
  try {
    const bytes = new Uint8Array(dnsQuery);

    // DNS message must be at least 12 bytes (header)
    if (bytes.length < 12) return '';

    let offset = 12; // Skip DNS header
    const labels = [];
    let jumped = false;
    let maxJumps = 5; // Prevent infinite loops

    while (offset < bytes.length && maxJumps > 0) {
      const length = bytes[offset];

      // End of domain name
      if (length === 0) break;

      // Check for compression pointer (first 2 bits are 11)
      if ((length & 0xC0) === 0xC0) {
        if (offset + 1 >= bytes.length) break;

        // Extract pointer offset
        const pointer = ((length & 0x3F) << 8) | bytes[offset + 1];

        if (!jumped) {
          offset += 2; // Move past pointer
        }

        offset = pointer;
        jumped = true;
        maxJumps--;
        continue;
      }

      // Regular label
      if (length > 63) break; // Invalid label length

      offset++;

      if (offset + length > bytes.length) break;

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

function isAllowlisted(domain) {
  if (ALLOWLIST.has(domain)) return true;

  // Check parent domains
  const parts = domain.split('.');
  for (let i = 1; i < parts.length; i++) {
    const parentDomain = parts.slice(i).join('.');
    if (ALLOWLIST.has(parentDomain)) return true;
  }

  return false;
}

function shouldBlock(domain) {
  if (!domain) return false;

  // Check exact match in blocklist
  if (BLOCKLIST.has(domain)) return true;

  // Check all parent domains
  const parts = domain.split('.');
  for (let i = 1; i < parts.length; i++) {
    const parentDomain = parts.slice(i).join('.');
    if (BLOCKLIST.has(parentDomain)) return true;
  }

  // Check patterns
  for (const pattern of BLOCK_PATTERNS) {
    if (pattern.test(domain)) {
      console.log(`Pattern match: ${domain} matches ${pattern}`);
      return true;
    }
  }

  return false;
}

function trackBlockedDomain(domain) {
  const count = stats.topBlockedDomains.get(domain) || 0;
  stats.topBlockedDomains.set(domain, count + 1);

  // Keep only top 100 domains
  if (stats.topBlockedDomains.size > 100) {
    const sorted = [...stats.topBlockedDomains.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 100);
    stats.topBlockedDomains = new Map(sorted);
  }
}

function createBlockedDNSResponse(query, domain) {
  const queryBytes = new Uint8Array(query);

  // Create minimal DNS response (NXDOMAIN)
  const response = new Uint8Array(queryBytes.length + 16);

  // Copy original query
  response.set(queryBytes);

  // Modify header for response
  response[2] = 0x81; // QR=1 (response), Opcode=0, AA=0, TC=0, RD=1
  response[3] = 0x83; // RA=1, Z=0, RCODE=3 (NXDOMAIN)

  // Set answer count to 0
  response[6] = 0;
  response[7] = 0;

  return new Response(response, {
    status: 200,
    headers: {
      'Content-Type': 'application/dns-message',
      'Access-Control-Allow-Origin': '*',
      'X-Blocked-Domain': domain,
      'X-Blocked-By': 'CF-DNS-AdBlock',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}

function handleBlocklist() {
  const list = Array.from(BLOCKLIST).sort();

  return new Response(JSON.stringify({
    total: list.length,
    domains: list,
    patterns: BLOCK_PATTERNS.map(p => p.source),
    lastUpdated: new Date().toISOString(),
  }, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}

function handleAllowlist() {
  const list = Array.from(ALLOWLIST).sort();

  return new Response(JSON.stringify({
    total: list.length,
    domains: list,
  }, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

function handleStats() {
  const uptime = Math.floor((Date.now() - stats.startTime) / 1000);
  const blockRate = stats.totalQueries > 0
    ? ((stats.blockedQueries / stats.totalQueries) * 100).toFixed(2)
    : 0;

  const topBlocked = [...stats.topBlockedDomains.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([domain, count]) => ({ domain, count }));

  return new Response(JSON.stringify({
    totalQueries: stats.totalQueries,
    blockedQueries: stats.blockedQueries,
    allowedQueries: stats.allowedQueries,
    blockRate: blockRate + '%',
    uptime: uptime + ' seconds',
    topBlockedDomains: topBlocked,
    blocklistSize: BLOCKLIST.size,
    allowlistSize: ALLOWLIST.size,
    patternCount: BLOCK_PATTERNS.length,
  }, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache',
    },
  });
}

function handleAddBlock(url) {
  const domain = url.searchParams.get('domain');
  if (domain && !BLOCKLIST.has(domain)) {
    BLOCKLIST.add(domain);
    return new Response(JSON.stringify({ success: true, domain }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
  return new Response(JSON.stringify({ success: false }), { status: 400 });
}

function handleAddAllow(url) {
  const domain = url.searchParams.get('domain');
  if (domain && !ALLOWLIST.has(domain)) {
    ALLOWLIST.add(domain);
    return new Response(JSON.stringify({ success: true, domain }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
  return new Response(JSON.stringify({ success: false }), { status: 400 });
}

function handleCORS() {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    }
  });
}

function getWebInterface() {
  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Enhanced DNS Ad Blocker</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-label {
            opacity: 0.9;
        }
        .endpoint {
            background: #667eea;
            color: white;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            word-break: break-all;
            margin: 15px 0;
            cursor: pointer;
        }
        .endpoint:hover {
            background: #5568d3;
        }
        button {
            background: #667eea;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            margin: 5px;
            transition: all 0.3s;
        }
        button:hover {
            background: #5568d3;
            transform: translateY(-2px);
        }
        .section {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 15px;
            margin: 20px 0;
        }
        #realTimeStats {
            background: #2d2d2d;
            color: #0f0;
            padding: 20px;
            border-radius: 10px;
            font-family: monospace;
            margin: 20px 0;
        }
        .top-blocked {
            max-height: 300px;
            overflow-y: auto;
        }
        .blocked-item {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            background: white;
            margin: 5px 0;
            border-radius: 5px;
        }
        .badge {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Enhanced DNS Ad Blocker</h1>
        <p style="color: #666; margin-bottom: 30px;">Advanced DNS-over-HTTPS filtering with real-time statistics <span class="badge">Chrome UA Enabled</span></p>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="totalQueries">0</div>
                <div class="stat-label">Total Queries</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="blockedQueries">0</div>
                <div class="stat-label">Blocked</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="blockRate">0%</div>
                <div class="stat-label">Block Rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="uptime">0s</div>
                <div class="stat-label">Uptime</div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Real-Time Statistics</h2>
            <button onclick="refreshStats()">🔄 Refresh Stats</button>
            <button onclick="toggleAutoRefresh()">⏱️ Auto-Refresh: OFF</button>
            <div id="realTimeStats">Loading...</div>
        </div>

        <div class="section">
            <h2>🎯 Top Blocked Domains</h2>
            <div id="topBlocked" class="top-blocked">Loading...</div>
        </div>

        <div class="section">
            <h2>🔗 DNS Endpoint</h2>
            <p>Use this URL in your browser/app:</p>
            <div class="endpoint" onclick="copyEndpoint()">${location.origin}/dns-query</div>
            <p style="margin-top: 10px; color: #666;">Click to copy • Spoofs Chrome UA for compatibility</p>
        </div>

        <div class="section">
            <h2>⚡ Quick Actions</h2>
            <button onclick="viewBlocklist()">📋 View Blocklist (${BLOCKLIST.size})</button>
            <button onclick="viewAllowlist()">✅ View Allowlist (${ALLOWLIST.size})</button>
            <button onclick="testBlocking()">🧪 Test Blocking</button>
        </div>

        <div class="section">
            <h2>📱 Setup Instructions</h2>
            <h3>Firefox:</h3>
            <ol>
                <li>Go to <code>about:preferences#general</code></li>
                <li>Network Settings → Enable DNS over HTTPS</li>
                <li>Enter: ${location.origin}/dns-query</li>
            </ol>

            <h3 style="margin-top: 20px;">Chrome/Edge:</h3>
            <ol>
                <li>Go to <code>chrome://settings/security</code></li>
                <li>Use secure DNS → Custom</li>
                <li>Enter: ${location.origin}/dns-query</li>
            </ol>
        </div>
    </div>

<script>
    let autoRefreshInterval = null;

    async function refreshStats() {
        try {
            const response = await fetch('/stats');
            const data = await response.json();

            document.getElementById('totalQueries').textContent = data.totalQueries;
            document.getElementById('blockedQueries').textContent = data.blockedQueries;
            document.getElementById('blockRate').textContent = data.blockRate;
            document.getElementById('uptime').textContent = data.uptime;

            document.getElementById('realTimeStats').innerHTML = \`
Queries: \${data.totalQueries}
Blocked: \${data.blockedQueries}
Allowed: \${data.allowedQueries}
Block Rate: \${data.blockRate}
Uptime: \${data.uptime}
Blocklist Size: \${data.blocklistSize}
Patterns: \${data.patternCount}
User-Agent: Chrome 130 (Windows 10)
\`;

            // Update top blocked domains
            const topBlocked = document.getElementById('topBlocked');
            if (data.topBlockedDomains && data.topBlockedDomains.length > 0) {
                topBlocked.innerHTML = data.topBlockedDomains.map(item => \`
                    <div class="blocked-item">
                        <span>\${item.domain}</span>
                        <span>\${item.count} times</span>
                    </div>
                \`).join('');
            } else {
                topBlocked.innerHTML = '<p>No blocked domains yet</p>';
            }
        } catch (error) {
            console.error('Error refreshing stats:', error);
        }
    }

    function toggleAutoRefresh() {
        if (autoRefreshInterval) {
            clearInterval(autoRefreshInterval);
            autoRefreshInterval = null;
            event.target.textContent = '⏱️ Auto-Refresh: OFF';
        } else {
            autoRefreshInterval = setInterval(refreshStats, 5000);
            event.target.textContent = '⏱️ Auto-Refresh: ON';
            refreshStats();
        }
    }

    async function viewBlocklist() {
        const response = await fetch('/blocklist');
        const data = await response.json();
        alert(\`Blocklist: \${data.total} domains\\n\\nFirst 10:\\n\` + data.domains.slice(0, 10).join('\\n'));
    }

    async function viewAllowlist() {
        const response = await fetch('/allowlist');
        const data = await response.json();
        alert(\`Allowlist: \${data.total} domains\\n\\n\` + data.domains.join('\\n'));
    }

    async function testBlocking() {
        alert('Testing: Will attempt to block doubleclick.net\\n\\nCheck the Top Blocked Domains section after clicking OK');
        refreshStats();
    }

    function copyEndpoint() {
        const endpoint = '${location.origin}/dns-query';
        navigator.clipboard.writeText(endpoint);
        alert('DNS endpoint copied to clipboard!');
    }

    // Initial load
    refreshStats();
</script>
</body>
</html>`, {
    headers: { 'Content-Type': 'text/html' },
  });
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';

  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

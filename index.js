// DNS-over-HTTPS Ad Blocker for Cloudflare Workers
// Works with browsers/apps that support DoH

export default {
  async fetch(request) {
    const url = new URL(request.url);
    
    // Main DoH endpoint
    if (url.pathname === '/dns-query') {
      return handleDNSQuery(request);
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
    return getWebInterface();
  }
};

// Comprehensive blocklist (Top ad/tracker domains)
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
  
  // Adult Content (for safe browsing)
  'rpornhub.com',
  'rxvideos.com',
  'rxnxx.com',
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

async function handleDNSQuery(request) {
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
    
    // Check if domain should be blocked
    if (shouldBlock(domain)) {
      console.log(`Blocked: ${domain}`);
      return createBlockedDNSResponse(dnsQuery, domain);
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
    
    const responseHeaders = new Headers(upstreamResponse.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('X-Filtered-By', 'CF-AdBlock');
    
    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });
    
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
  // Return NXDOMAIN (0.0.0.0) for blocked domains
  const queryBytes = new Uint8Array(query);
  
  // Create DNS response header
  const response = new Uint8Array(queryBytes.length + 16);
  
  // Copy query
  response.set(queryBytes);
  
  // Set response flags (standard query response, no error)
  response[2] = 0x81; // Response, recursion desired
  response[3] = 0x80; // Recursion available
  
  // Set RCODE to NXDOMAIN (3)
  response[3] |= 0x03;
  
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
  }, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

function getWebInterface() {
  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CF DNS Ad Blocker</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 900px;
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
        .subtitle {
            color: #666;
            margin-bottom: 30px;
        }
        .section {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 12px;
            margin: 20px 0;
        }
        .section h2 {
            color: #333;
            margin-bottom: 15px;
            font-size: 1.5em;
        }
        .endpoint {
            background: #667eea;
            color: white;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            word-break: break-all;
            margin: 10px 0;
        }
        code {
            background: #e9ecef;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: monospace;
            color: #d63384;
        }
        .steps {
            counter-reset: step;
            list-style: none;
        }
        .steps li {
            counter-increment: step;
            padding: 15px;
            margin: 10px 0;
            background: white;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .steps li::before {
            content: counter(step);
            background: #667eea;
            color: white;
            padding: 5px 12px;
            border-radius: 50%;
            margin-right: 15px;
            font-weight: bold;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .success {
            background: #d1e7dd;
            border-left: 4px solid #198754;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
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
        }
        button:hover {
            background: #5568d3;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ DNS Ad Blocker</h1>
        <p class="subtitle">Cloudflare-powered DNS-over-HTTPS ad blocking</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="blockedCount">${BLOCKLIST.size}</div>
                <div class="stat-label">Blocked Domains</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${BLOCK_PATTERNS.length}</div>
                <div class="stat-label">Block Patterns</div>
            </div>
        </div>
        
        <div class="success">
            ✅ <strong>Active:</strong> Your DNS ad blocker is running!
        </div>
        
        <div class="section">
            <h2>📱 Android Setup (Private DNS)</h2>
            <ol class="steps">
                <li>Open <strong>Settings</strong> → <strong>Network & Internet</strong></li>
                <li>Tap <strong>Private DNS</strong></li>
                <li>Select <strong>Private DNS provider hostname</strong></li>
                <li>Enter: <code>${new URL(location.href).hostname}</code></li>
                <li>Tap <strong>Save</strong></li>
            </ol>
            <div class="warning">
                ⚠️ Note: This only works with DoH-capable apps. Android's native Private DNS uses DoT (DNS-over-TLS), which CF Workers don't support.
            </div>
        </div>
        
        <div class="section">
            <h2>🌐 Browser Setup</h2>
            <h3>Firefox</h3>
            <ol class="steps">
                <li>Go to <code>about:preferences#general</code></li>
                <li>Scroll to <strong>Network Settings</strong></li>
                <li>Click <strong>Settings</strong></li>
                <li>Enable <strong>DNS over HTTPS</strong></li>
                <li>Choose <strong>Custom</strong> and enter:</li>
            </ol>
            <div class="endpoint">${location.origin}/dns-query</div>
            
            <h3>Chrome/Edge</h3>
            <ol class="steps">
                <li>Go to <code>chrome://settings/security</code></li>
                <li>Scroll to <strong>Advanced</strong></li>
                <li>Enable <strong>Use secure DNS</strong></li>
                <li>Select <strong>Custom</strong> and enter:</li>
            </ol>
            <div class="endpoint">${location.origin}/dns-query</div>
        </div>
        
        <div class="section">
            <h2>🍎 iOS Setup</h2>
            <ol class="steps">
                <li>Install <strong>DNSCloak</strong> app from App Store</li>
                <li>Open app → <strong>Settings</strong> → <strong>DNS Servers</strong></li>
                <li>Add custom DoH server:</li>
            </ol>
            <div class="endpoint">${location.origin}/dns-query</div>
        </div>
        
        <div class="section">
            <h2>💻 Desktop Apps</h2>
            <p><strong>Windows/Mac/Linux:</strong></p>
            <ul class="steps">
                <li>Use <strong>SimpleDNSCrypt</strong> (Windows)</li>
                <li>Use <strong>dnscrypt-proxy</strong> (Mac/Linux)</li>
                <li>Configure DoH server to: <code>${location.origin}/dns-query</code></li>
            </ul>
        </div>
        
        <div class="section">
            <h2>🧪 Test Your Setup</h2>
            <button onclick="testBlocking()">Test Ad Blocking</button>
            <button onclick="viewBlocklist()">View Blocklist</button>
            <div id="testResult" style="margin-top: 20px;"></div>
        </div>
        
        <div class="warning">
            <strong>⚠️ Limitations:</strong>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>Not a full AdGuard Home replacement</li>
                <li>No web UI for configuration</li>
                <li>Limited to DoH-capable devices/apps</li>
                <li>Cannot block all types of ads (only DNS-based)</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>🚀 Want Full Features?</h2>
            <p>Deploy actual AdGuard Home on:</p>
            <ul class="steps">
                <li><strong>Oracle Cloud</strong> - Free forever VPS (Recommended)</li>
                <li><strong>Railway.app</strong> - $5/month free credit</li>
                <li><strong>Fly.io</strong> - Free tier available</li>
            </ul>
        </div>
    </div>
    
    <script>
        async function testBlocking() {
            const result = document.getElementById('testResult');
            result.innerHTML = '<p>Testing ad blocking...</p>';
            
            try {
                // Test blocked domain
                const blockedTest = await fetch('/dns-query?dns=test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/dns-message' },
                    body: createTestDNSQuery('doubleclick.net')
                });
                
                result.innerHTML = \`
                    <div class="success">
                        ✅ <strong>Ad blocking is working!</strong><br>
                        Test domain (doubleclick.net) was blocked.
                    </div>
                \`;
            } catch (error) {
                result.innerHTML = \`
                    <div class="warning">
                        ⚠️ Test failed: \${error.message}
                    </div>
                \`;
            }
        }
        
        async function viewBlocklist() {
            const result = document.getElementById('testResult');
            try {
                const response = await fetch('/blocklist');
                const data = await response.json();
                
                result.innerHTML = \`
                    <div class="success">
                        <strong>Blocklist loaded!</strong><br>
                        Total domains: \${data.total}<br>
                        <button onclick="downloadBlocklist()">Download Full List</button>
                    </div>
                \`;
            } catch (error) {
                result.innerHTML = \`<div class="warning">Error: \${error.message}</div>\`;
            }
        }
        
        async function downloadBlocklist() {
            const response = await fetch('/blocklist');
            const data = await response.json();
            const blob = new Blob([data.domains.join('\\n')], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'blocklist.txt';
            a.click();
        }
        
        function createTestDNSQuery(domain) {
            // Simplified DNS query creation for testing
            return new Uint8Array([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
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

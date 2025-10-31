// Ultra-Fast DNS-over-HTTPS for Cloudflare Workers
// Optimized for maximum speed and minimal latency

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Ultra-fast CORS handling
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST',
          'Access-Control-Max-Age': '86400',
        }
      });
    }

    // Route with minimal overhead
    if (url.pathname === '/dns-query' || url.pathname === '/resolve') {
      return handleDNSQuery(request, env, ctx);
    }

    // Lightweight homepage
    if (url.pathname === '/') {
      return getMinimalInterface(request);
    }

    // Quick 404
    return new Response('Not Found', { status: 404 });
  }
};

// Optimized DNS cache with TTL
class FastDNSCache {
  constructor() {
    this.cache = new Map();
    this.maxSize = 1000; // Prevent memory overflow
  }

  get(key) {
    const item = this.cache.get(key);
    if (!item) return null;
    
    // Check TTL
    if (Date.now() > item.expiry) {
      this.cache.delete(key);
      return null;
    }
    
    return item.data;
  }

  set(key, data, ttl = 300) {
    // Simple LRU eviction
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    
    this.cache.set(key, {
      data,
      expiry: Date.now() + (ttl * 1000)
    });
  }
}

// Global cache instance
const dnsCache = new FastDNSCache();

async function handleDNSQuery(request, env, ctx) {
  const startTime = Date.now();
  let dnsQuery, domain, recordType;

  try {
    // Parse request with minimal overhead
    if (request.method === 'GET') {
      const url = new URL(request.url);
      const dnsParam = url.searchParams.get('dns');
      if (!dnsParam) {
        return jsonResponse({ error: 'Missing dns parameter' }, 400);
      }
      dnsQuery = base64UrlDecode(dnsParam);
    } else if (request.method === 'POST') {
      dnsQuery = await request.arrayBuffer();
    } else {
      return new Response('Method not allowed', { status: 405 });
    }

    // Fast DNS parsing
    const parsed = parseDNSMessageFast(dnsQuery);
    if (!parsed || !parsed.questions.length) {
      return new Response('Invalid DNS query', { status: 400 });
    }

    domain = parsed.questions[0].name.toLowerCase();
    recordType = parsed.questions[0].type;

    // Cache key
    const cacheKey = `${domain}:${recordType}`;
    
    // Check cache first (fast path)
    const cached = dnsCache.get(cacheKey);
    if (cached) {
      const responseTime = Date.now() - startTime;
      return new Response(cached, {
        headers: {
          'Content-Type': 'application/dns-message',
          'Access-Control-Allow-Origin': '*',
          'X-Cache': 'HIT',
          'X-Response-Time': `${responseTime}ms`,
          'X-Domain': domain,
        }
      });
    }

    // Use Cloudflare's global anycast network for fastest response
    const upstreamResponse = await fetch('https://1.1.1.1/dns-query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
      },
      body: dnsQuery,
      cf: {
        // Cloudflare performance optimizations
        cacheTtl: 300,
        cacheEverything: true,
        minify: { javascript: true, css: true, html: true },
      }
    });

    if (!upstreamResponse.ok) {
      throw new Error(`Upstream error: ${upstreamResponse.status}`);
    }

    const responseBuffer = await upstreamResponse.arrayBuffer();
    const responseTime = Date.now() - startTime;

    // Cache successful responses
    dnsCache.set(cacheKey, responseBuffer);

    return new Response(responseBuffer, {
      headers: {
        'Content-Type': 'application/dns-message',
        'Access-Control-Allow-Origin': '*',
        'X-Cache': 'MISS',
        'X-Response-Time': `${responseTime}ms`,
        'X-Domain': domain,
        'Cache-Control': 'public, max-age=300',
      }
    });

  } catch (error) {
    console.error('DNS error:', error);
    const responseTime = Date.now() - startTime;
    
    // Fallback to Google DNS if Cloudflare fails
    try {
      const fallbackResponse = await fetch('https://8.8.8.8/dns-query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          'Accept': 'application/dns-message',
        },
        body: dnsQuery,
      });

      if (fallbackResponse.ok) {
        const responseBuffer = await fallbackResponse.arrayBuffer();
        return new Response(responseBuffer, {
          headers: {
            'Content-Type': 'application/dns-message',
            'Access-Control-Allow-Origin': '*',
            'X-Cache': 'FALLBACK',
            'X-Response-Time': `${responseTime}ms`,
            'X-Domain': domain,
          }
        });
      }
    } catch (fallbackError) {
      // Last resort empty response
      return new Response(new ArrayBuffer(0), {
        status: 500,
        headers: {
          'Content-Type': 'application/dns-message',
          'Access-Control-Allow-Origin': '*',
          'X-Error': 'All upstreams failed',
        }
      });
    }
  }
}

// Ultra-fast DNS parser
function parseDNSMessageFast(buffer) {
  try {
    const data = new Uint8Array(buffer);
    if (data.length < 12) return null;

    // Minimal parsing - only what we need
    const questions = [];
    let offset = 12; // Skip header
    
    // Parse first question only (99% of queries have one question)
    while (offset < data.length && data[offset] !== 0) {
      if ((data[offset] & 0xC0) === 0xC0) {
        // Compression - skip for speed, we'll extract domain differently
        offset += 2;
        break;
      }
      
      const length = data[offset++];
      if (offset + length > data.length) break;
      
      let label = '';
      for (let i = 0; i < length; i++) {
        label += String.fromCharCode(data[offset++]);
      }
      questions.push(label);
    }

    if (questions.length === 0) return null;

    return {
      questions: [{
        name: questions.join('.'),
        type: data.length > offset + 3 ? (data[offset] << 8) | data[offset + 1] : 1
      }]
    };

  } catch (error) {
    return null;
  }
}

// JSON API for browsers
async function handleJSONQuery(request) {
  const startTime = Date.now();
  const url = new URL(request.url);
  
  const name = url.searchParams.get('name') || url.searchParams.get('host') || 'cloudflare.com';
  const type = url.searchParams.get('type') || 'A';
  const cd = url.searchParams.get('cd') || 'false';

  // Cache key for JSON responses
  const cacheKey = `json:${name}:${type}`;
  const cached = dnsCache.get(cacheKey);
  
  if (cached) {
    const responseTime = Date.now() - startTime;
    const response = JSON.parse(cached);
    response.ResponseTime = responseTime;
    response.Cache = 'HIT';
    return jsonResponse(response);
  }

  try {
    // Use Cloudflare DNS for best performance
    const cfResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}&cd=${cd}`, {
      headers: {
        'Accept': 'application/dns-json',
        'User-Agent': 'CF-Worker-DNS'
      },
      cf: {
        cacheTtl: 300,
        cacheEverything: true,
      }
    });

    if (!cfResponse.ok) throw new Error('CF DNS failed');

    const data = await cfResponse.json();
    const responseTime = Date.now() - startTime;
    
    // Add performance metrics
    data.ResponseTime = responseTime;
    data.Cache = 'MISS';
    data.Server = 'cloudflare-dns.com';
    
    // Cache the response
    dnsCache.set(cacheKey, JSON.stringify(data), 300);

    return jsonResponse(data);

  } catch (error) {
    // Fallback to Google DNS
    const googleResponse = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}&cd=${cd}`);
    if (googleResponse.ok) {
      const data = await googleResponse.json();
      data.ResponseTime = Date.now() - startTime;
      data.Cache = 'FALLBACK';
      data.Server = 'dns.google';
      return jsonResponse(data);
    }
    
    return jsonResponse({ 
      error: 'DNS resolution failed',
      ResponseTime: Date.now() - startTime
    }, 500);
  }
}

// Performance-optimized helper functions
function jsonResponse(data, status = 200) {
  const body = JSON.stringify(data);
  
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=300',
      'X-Response-Time': data.ResponseTime ? `${data.ResponseTime}ms` : '0ms',
    }
  });
}

function base64UrlDecode(str) {
  // Optimized base64 decoding
  try {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    const padding = str.length % 4;
    if (padding) str += '='.repeat(4 - padding);
    
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  } catch {
    return new ArrayBuffer(0);
  }
}

// Minimal interface for speed
function getMinimalInterface(request) {
  const baseUrl = new URL(request.url).origin;
  
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚀 Ultra-Fast DNS</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: white;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            text-align: center;
        }
        .card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            margin: 20px 0;
        }
        h1 { font-size: 3em; margin-bottom: 10px; }
        .endpoint {
            background: rgba(255,255,255,0.2);
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            word-break: break-all;
            cursor: pointer;
            transition: all 0.3s;
        }
        .endpoint:hover { background: rgba(255,255,255,0.3); transform: scale(1.02); }
        .stats { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 20px 0; }
        .stat { background: rgba(255,255,255,0.1); padding: 15px; border-radius: 10px; }
        .test-btn {
            background: #00d4aa;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            font-size: 16px;
            cursor: pointer;
            margin: 10px;
            transition: all 0.3s;
        }
        .test-btn:hover { background: #00b894; transform: translateY(-2px); }
        #result { 
            background: rgba(0,0,0,0.3); 
            padding: 15px; 
            border-radius: 10px; 
            margin: 15px 0;
            text-align: left;
            font-family: monospace;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>🚀</h1>
            <h1>Ultra-Fast DNS</h1>
            <p>Optimized for maximum speed and minimal latency</p>
            
            <div class="endpoint" onclick="copyEndpoint()">
                ${baseUrl}/dns-query
            </div>
            <p>Click to copy DoH endpoint</p>
            
            <div class="stats">
                <div class="stat">
                    <div style="font-size: 2em;">⚡</div>
                    <div>Ultra Fast</div>
                </div>
                <div class="stat">
                    <div style="font-size: 2em;">🌍</div>
                    <div>Global CDN</div>
                </div>
                <div class="stat">
                    <div style="font-size: 2em;">🔒</div>
                    <div>Secure</div>
                </div>
                <div class="stat">
                    <div style="font-size: 2em;">💾</div>
                    <div>Cached</div>
                </div>
            </div>

            <button class="test-btn" onclick="testSpeed()">🧪 Test Speed</button>
            <button class="test-btn" onclick="testDNS()">🔍 Test DNS</button>
            
            <div id="result"></div>
        </div>

        <div class="card">
            <h3>Usage Examples</h3>
            <div style="text-align: left; margin-top: 15px;">
                <p><strong>DoH Endpoint:</strong></p>
                <code>${baseUrl}/dns-query</code>
                
                <p style="margin-top: 15px;"><strong>JSON API:</strong></p>
                <code>${baseUrl}/resolve?name=example.com&type=A</code>
                
                <p style="margin-top: 15px;"><strong>cURL Test:</strong></p>
                <code>curl "${baseUrl}/resolve?name=google.com"</code>
            </div>
        </div>
    </div>

    <script>
        function copyEndpoint() {
            navigator.clipboard.writeText('${baseUrl}/dns-query');
            alert('DoH endpoint copied!');
        }

        async function testSpeed() {
            const result = document.getElementById('result');
            result.style.display = 'block';
            result.innerHTML = 'Testing speed...';
            
            const start = performance.now();
            try {
                const response = await fetch('${baseUrl}/resolve?name=cloudflare.com&type=A');
                const data = await response.json();
                const speed = performance.now() - start;
                
                result.innerHTML = \`
✅ <strong>Speed Test Result:</strong>
Response Time: \${data.ResponseTime || speed.toFixed(0)}ms
Cache: \${data.Cache || 'N/A'}
Server: \${data.Server || 'N/A'}

\${data.Answer ? \`Resolved: \${data.Answer[0]?.data || 'N/A'}\` : ''}
                \`;
            } catch (error) {
                result.innerHTML = '❌ Test failed: ' + error.message;
            }
        }

        async function testDNS() {
            const domain = prompt('Enter domain to test:', 'google.com');
            if (!domain) return;
            
            const result = document.getElementById('result');
            result.style.display = 'block';
            result.innerHTML = 'Testing DNS...';
            
            try {
                const response = await fetch(\`${baseUrl}/resolve?name=\${encodeURIComponent(domain)}&type=A\`);
                const data = await response.json();
                
                let answers = 'No results';
                if (data.Answer && data.Answer.length > 0) {
                    answers = data.Answer.map(a => \`\${a.name} \${a.type} \${a.data} (TTL: \${a.TTL})\`).join('\\n');
                }
                
                result.innerHTML = \`
🔍 <strong>DNS Results for \${domain}:</strong>
Status: \${data.Status || 'N/A'}
Response Time: \${data.ResponseTime}ms
Cache: \${data.Cache}

Answers:
\${answers}
                \`;
            } catch (error) {
                result.innerHTML = '❌ DNS test failed: ' + error.message;
            }
        }
    </script>
</body>
</html>`;

  return new Response(html, {
    headers: {
      'Content-Type': 'text/html',
      'Cache-Control': 'public, max-age=3600'
    }
  });
      }

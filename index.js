// 🛡️ Enhanced DNS-over-HTTPS Ad Blocker for Cloudflare Workers
// Version: Chrome UA Global Edition (2025)
// Features:
// ✅ Global Chrome User-Agent Spoof (all fetches)
// ✅ DNS-over-HTTPS Blocking
// ✅ Allowlist / Blocklist
// ✅ Pattern-based Filtering
// ✅ Live Statistics + Web UI
// ✅ 100% Safe for Cloudflare Free Plan

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") return handleCORS();

    switch (url.pathname) {
      case "/dns-query":
        return handleDNSQuery(request, ctx);
      case "/blocklist":
        return handleBlocklist();
      case "/allowlist":
        return handleAllowlist();
      case "/stats":
        return handleStats();
      case "/add-block":
        return handleAddBlock(url);
      case "/add-allow":
        return handleAddAllow(url);
      default:
        return getWebInterface();
    }
  },
};

// === GLOBAL CONSTANTS ===
const GLOBAL_HEADERS = {
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
  Referer: "https://www.google.com/",
};

const BLOCKLIST = new Set([
  "doubleclick.net", "googleadservices.com", "googlesyndication.com",
  "pagead2.googlesyndication.com", "adservice.google.com", "ads.google.com",
  "google-analytics.com", "googletagmanager.com", "analytics.google.com",
  "stats.g.doubleclick.net", "ad.doubleclick.net", "pubads.g.doubleclick.net",
  "facebook.net", "connect.facebook.net", "pixel.facebook.com",
  "adnxs.com", "advertising.com", "adsrvr.org", "smartadserver.com",
  "criteo.com", "outbrain.com", "taboola.com", "adform.net", "admob.com",
  "mixpanel.com", "segment.com", "hotjar.com", "crazyegg.com", "fullstory.com",
  "analytics.tiktok.com", "ads-api.tiktok.com", "ads.twitter.com",
  "ads.youtube.com", "video-ad-stats.googlesyndication.com",
  "propellerads.com", "popads.net", "adsterra.com", "exoclick.com",
  "juicyads.com", "hilltopads.net", "trafficjunky.com", "adserver.juicyads.com",
  "coinhive.com", "coin-hive.com", "jsecoin.com", "crypto-loot.com",
  "malware-traffic.com", "phishing-site.com", "badware.com",
  "scorecardresearch.com", "quantserve.com", "chartbeat.com",
]);

const ALLOWLIST = new Set([
  "google.com", "youtube.com", "facebook.com", "twitter.com",
  "instagram.com", "reddit.com", "wikipedia.org", "github.com",
  "stackoverflow.com", "amazon.com", "netflix.com", "cloudflare.com",
]);

const BLOCK_PATTERNS = [
  /^ads?\d*\./i, /^analytics?\./i, /^tracking?\./i, /^telemetry\./i,
  /^metrics?\./i, /[-_.]ad[-_.]/i, /[-_.]ads[-_.]/i, /[-_.]tracker[-_.]/i,
  /[-_.]tracking[-_.]/i, /^advert/i, /^banner/i, /^click/i, /^pixel/i, /^tag/i,
];

// === STATS ===
let stats = {
  totalQueries: 0,
  blockedQueries: 0,
  allowedQueries: 0,
  topBlockedDomains: new Map(),
  startTime: Date.now(),
};

// === HANDLERS ===
async function handleDNSQuery(request, ctx) {
  stats.totalQueries++;

  try {
    const url = new URL(request.url);
    let dnsQuery;

    if (request.method === "GET" && url.searchParams.has("dns")) {
      dnsQuery = base64UrlDecode(url.searchParams.get("dns"));
    } else if (request.method === "POST") {
      dnsQuery = await request.arrayBuffer();
    } else {
      return new Response("Invalid DNS query method", { status: 400 });
    }

    const domain = parseDomainFromDNS(dnsQuery);
    if (!domain) return forwardToUpstream(dnsQuery);

    if (isAllowlisted(domain)) {
      stats.allowedQueries++;
      return forwardToUpstream(dnsQuery);
    }

    if (shouldBlock(domain)) {
      stats.blockedQueries++;
      trackBlockedDomain(domain);
      console.log(`🚫 Blocked: ${domain}`);
      return createBlockedDNSResponse(dnsQuery, domain);
    }

    stats.allowedQueries++;
    return forwardToUpstream(dnsQuery);
  } catch (error) {
    console.error("DNS query error:", error);
    return forwardToUpstream(await request.arrayBuffer());
  }
}

// === Global Chrome UA fetch() Wrapper ===
async function fetchWithUA(url, options = {}) {
  options.headers = { ...(options.headers || {}), ...GLOBAL_HEADERS };
  return await fetch(url, options);
}

// === Upstream Resolver ===
async function forwardToUpstream(dnsQuery) {
  const upstreamURL = "https://cloudflare-dns.com/dns-query";
  try {
    const upstreamResponse = await fetchWithUA(upstreamURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      body: dnsQuery,
      cf: { cacheTtl: 300 },
    });

    const headers = new Headers(upstreamResponse.headers);
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("X-Filtered-By", "CF-DNS-AdBlock");
    headers.set("X-Upstream", "Cloudflare");
    headers.set("X-UA", GLOBAL_HEADERS["User-Agent"]);

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers,
    });
  } catch (error) {
    console.error("Upstream DNS error:", error);
    return new Response("DNS resolution failed", { status: 502 });
  }
}

// === Parsing / Logic ===
function parseDomainFromDNS(dnsQuery) {
  try {
    const bytes = new Uint8Array(dnsQuery);
    if (bytes.length < 12) return "";
    let offset = 12, labels = [];
    while (offset < bytes.length) {
      const len = bytes[offset++];
      if (len === 0) break;
      labels.push(String.fromCharCode(...bytes.slice(offset, offset + len)));
      offset += len;
    }
    return labels.join(".").toLowerCase();
  } catch {
    return "";
  }
}

function isAllowlisted(domain) {
  if (ALLOWLIST.has(domain)) return true;
  const parts = domain.split(".");
  for (let i = 1; i < parts.length; i++) {
    if (ALLOWLIST.has(parts.slice(i).join("."))) return true;
  }
  return false;
}

function shouldBlock(domain) {
  if (!domain) return false;
  if (BLOCKLIST.has(domain)) return true;
  const parts = domain.split(".");
  for (let i = 1; i < parts.length; i++) {
    if (BLOCKLIST.has(parts.slice(i).join("."))) return true;
  }
  return BLOCK_PATTERNS.some((p) => p.test(domain));
}

function trackBlockedDomain(domain) {
  const count = stats.topBlockedDomains.get(domain) || 0;
  stats.topBlockedDomains.set(domain, count + 1);
  if (stats.topBlockedDomains.size > 100) {
    stats.topBlockedDomains = new Map(
      [...stats.topBlockedDomains.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 100)
    );
  }
}

// === DNS Response ===
function createBlockedDNSResponse(query, domain) {
  const q = new Uint8Array(query);
  const r = new Uint8Array(q.length + 16);
  r.set(q);
  r[2] = 0x81;
  r[3] = 0x83;
  r[6] = 0;
  r[7] = 0;
  return new Response(r, {
    status: 200,
    headers: {
      "Content-Type": "application/dns-message",
      "Access-Control-Allow-Origin": "*",
      "X-Blocked-Domain": domain,
      "X-UA": GLOBAL_HEADERS["User-Agent"],
      "X-Blocked-By": "CF-DNS-AdBlock",
    },
  });
}

// === API / Stats ===
function handleBlocklist() {
  return jsonResponse({
    total: BLOCKLIST.size,
    domains: [...BLOCKLIST],
    patterns: BLOCK_PATTERNS.map((r) => r.source),
  });
}

function handleAllowlist() {
  return jsonResponse({
    total: ALLOWLIST.size,
    domains: [...ALLOWLIST],
  });
}

function handleStats() {
  const uptime = Math.floor((Date.now() - stats.startTime) / 1000);
  const blockRate =
    stats.totalQueries > 0
      ? ((stats.blockedQueries / stats.totalQueries) * 100).toFixed(2)
      : 0;
  const topBlocked = [...stats.topBlockedDomains.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([domain, count]) => ({ domain, count }));

  return jsonResponse({
    totalQueries: stats.totalQueries,
    blockedQueries: stats.blockedQueries,
    allowedQueries: stats.allowedQueries,
    blockRate: blockRate + "%",
    uptime: uptime + "s",
    topBlockedDomains: topBlocked,
    ua: GLOBAL_HEADERS["User-Agent"],
  });
}

// === Helpers ===
function handleAddBlock(url) {
  const domain = url.searchParams.get("domain");
  if (domain && !BLOCKLIST.has(domain)) {
    BLOCKLIST.add(domain);
    return jsonResponse({ success: true, domain });
  }
  return jsonResponse({ success: false }, 400);
}

function handleAddAllow(url) {
  const domain = url.searchParams.get("domain");
  if (domain && !ALLOWLIST.has(domain)) {
    ALLOWLIST.add(domain);
    return jsonResponse({ success: true, domain });
  }
  return jsonResponse({ success: false }, 400);
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function handleCORS() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
    },
  });
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// === Web UI ===
function getWebInterface() {
  return new Response(
    `<!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px">
    <h1>🛡️ Cloudflare DNS Ad Blocker</h1>
    <p><b>DNS Endpoint:</b> <code>${location.origin}/dns-query</code></p>
    <p><b>User-Agent:</b> ${GLOBAL_HEADERS["User-Agent"]}</p>
    <ul>
      <li><a href="/stats">/stats</a></li>
      <li><a href="/blocklist">/blocklist</a></li>
      <li><a href="/allowlist">/allowlist</a></li>
    </ul>
    <p style="color:gray;">Powered by Cloudflare Workers</p>
    </body></html>`,
    { headers: { "Content-Type": "text/html" } }
  );
}

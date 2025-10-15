export default {
  async fetch(request, env, ctx) {
    if (request.url.endsWith('/dns-query')) {
      return handleDNSQuery(request);
    }
    return new Response('DNS Ad Blocker Active', { status: 200 });
  }
};

const BLOCKLIST = new Set(['doubleclick.net']); // Minimal for testing

async function handleDNSQuery(request) {
  let dnsQuery;
  if (request.method === 'POST') {
    dnsQuery = await request.arrayBuffer();
  } else {
    return new Response('POST only', { status: 405 });
  }
  const domain = parseDomainFromDNS(dnsQuery);
  if (domain.includes('doubleclick')) { // Simple exact block
    return createBlockedDNSResponse(dnsQuery, domain);
  }
  const upstream = await fetch('https://cloudflare-dns.com/dns-query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/dns-message' },
    body: dnsQuery
  });
  return new Response(upstream.body, { headers: upstream.headers });
}

function parseDomainFromDNS(dnsQuery) {
  const bytes = new Uint8Array(dnsQuery);
  let offset = 12; // Skip header
  const labels = [];
  while (offset < bytes.length && bytes[offset] !== 0) {
    const len = bytes[offset++];
    const label = String.fromCharCode(...bytes.slice(offset, offset + len));
    labels.push(label);
    offset += len;
  }
  return labels.join('.').toLowerCase();
}

function createBlockedDNSResponse(query, domain) {
  const bytes = new Uint8Array(query);
  bytes[2] = 0x81; bytes[3] = 0x83; // NXDOMAIN flags
  return new Response(bytes, { status: 200, headers: { 'Content-Type': 'application/dns-message' } });
                      }

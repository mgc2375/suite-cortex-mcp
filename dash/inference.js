"use strict";
/* Inference engine for the strategic hunt.
 *
 * Turns raw tool output into typed SIGNALS (leads), maps each signal type to the
 * CAPABILITIES across the whole cortex surface that consume it (OSINT/identity,
 * web exploit, API, recon, supply-chain, cloud, web3, network), and produces
 * concrete ACTIONS the dispatcher runs:
 *   - {kind:'target',   target, cls, reason}        → queue a full hunt
 *   - {kind:'upstream', server, tool, args, reason} → call_upstream (specific tool)
 *   - {kind:'tool',     tool_id, args, reason}      → call_tool (registry entry)
 *   - {kind:'follow',   url, reason}                → fetch the page, extract more signals
 *
 * Active full hunts are created conservatively (in-scope subdomains / LAN IPs only);
 * passive intel lookups (whois/breach/etc.) run liberally since they're read-only.
 */

const SOCIAL_HOSTS = [
  { re: /(?:youtube\.com\/(?:@|channel\/|c\/|user\/)|youtu\.be\/)([A-Za-z0-9_\-.]+)/i, platform: "youtube" },
  { re: /github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)(?:\/([A-Za-z0-9._-]+))?/i, platform: "github" },
  { re: /(?:twitter|x)\.com\/([A-Za-z0-9_]{1,15})/i, platform: "twitter" },
  { re: /linkedin\.com\/(?:in|company)\/([A-Za-z0-9\-%]+)/i, platform: "linkedin" },
  { re: /instagram\.com\/([A-Za-z0-9_.]+)/i, platform: "instagram" },
  { re: /reddit\.com\/(?:user|u)\/([A-Za-z0-9_\-]+)/i, platform: "reddit" },
  { re: /keybase\.io\/([A-Za-z0-9_]+)/i, platform: "keybase" },
  { re: /tiktok\.com\/@([A-Za-z0-9_.]+)/i, platform: "tiktok" },
  { re: /steamcommunity\.com\/id\/([A-Za-z0-9_\-]+)/i, platform: "steam" },
];
const ASSET_EXT = /\.(png|jpe?g|gif|svg|webp|css|js|mjs|json|xml|woff2?|ttf|ico|map|txt|md|pdf)($|\?)/i;
const SKIP_DOMAINS = /(^|\.)(w3\.org|schema\.org|googleapis\.com|gstatic\.com|cloudflare\.com|jsdelivr\.net|unpkg\.com|fontawesome\.com|bootstrapcdn\.com|example\.com|localhost|youtube\.com|youtu\.be|github\.com|githubusercontent\.com|twitter\.com|x\.com|linkedin\.com|instagram\.com|facebook\.com|fbcdn\.net|reddit\.com|redd\.it|tiktok\.com|t\.me|telegram\.org|google\.com|gmail\.com|googletagmanager\.com|google-analytics\.com|doubleclick\.net|keybase\.io|steamcommunity\.com|apple\.com|microsoft\.com|bing\.com|mozilla\.org|wordpress\.org|wp\.com|gravatar\.com|ytimg\.com|ggpht\.com)$/i;

/* Same extractor cortex uses on tool output — applied here to followed-URL HTML. */
function extractSignals(raw) {
  const t = String(raw || "").slice(0, 300000);
  const out = [];
  const seen = new Set();
  const add = (type, value, meta) => {
    const v = String(value || "").trim().replace(/[.,);\]]+$/, "");
    if (!v) return;
    const k = type + ":" + v.toLowerCase();
    if (seen.has(k)) return;
    seen.add(k);
    out.push(meta ? Object.assign({ type, value: v }, meta) : { type, value: v });
  };
  for (const m of t.matchAll(/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g)) add("email", m[0].toLowerCase());
  const urls = [];
  for (const m of t.matchAll(/https?:\/\/[^\s"'<>)\]}]+/g)) urls.push(m[0].replace(/[.,);\]]+$/, ""));
  for (const u of urls) {
    let social = false;
    for (const s of SOCIAL_HOSTS) {
      const mm = u.match(s.re);
      if (mm) { add("social", u, { platform: s.platform, handle: mm[1] || "" }); if (mm[1]) add("username", mm[1], { platform: s.platform }); social = true; }
    }
    if (social) continue;
    if (/\.s3[.\-]|s3\.amazonaws\.com|\.blob\.core\.windows\.net|storage\.googleapis\.com|\.r2\.dev/i.test(u)) { add("bucket", u); continue; }
    if (/swagger|openapi|\/graphql\b|api-docs|\.wsdl/i.test(u)) add("api_spec", u);
    if (ASSET_EXT.test(u)) continue;
    add("url", u);
  }
  for (const m of t.matchAll(/\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b/gi)) {
    const d = m[1].toLowerCase();
    if (ASSET_EXT.test(d) || /\d+\.\d+\.\d+\.\d+/.test(d)) continue;
    add("domain", d);
  }
  for (const m of t.matchAll(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g)) {
    if ([m[1], m[2], m[3], m[4]].every((o) => +o <= 255)) add("ip", `${m[1]}.${m[2]}.${m[3]}.${m[4]}`);
  }
  for (const m of t.matchAll(/CVE-\d{4}-\d{4,7}/gi)) add("cve", m[0].toUpperCase());
  for (const m of t.matchAll(/\b([A-Za-z][A-Za-z0-9+.\-]{1,24})\/(\d+\.\d[\w.\-]*)/g)) add("tech", `${m[1]}/${m[2]}`, { product: m[1], version: m[2] });
  for (const m of t.matchAll(/\b0x[a-fA-F0-9]{40}\b/g)) add("eth", m[0]);
  for (const m of t.matchAll(/\bAS\d{2,6}\b/g)) add("asn", m[0]);
  if (/AKIA[0-9A-Z]{16}/.test(t)) add("secret", "aws_access_key");
  if (/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/.test(t)) add("secret", "private_key");
  if (/xox[baprs]-[0-9A-Za-z\-]{10,}/.test(t)) add("secret", "slack_token");
  return out.slice(0, 150);
}

function apexOf(host) {
  const h = String(host || "").toLowerCase().replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  const parts = h.split(".").filter(Boolean);
  if (parts.length <= 2) return h;
  const twoLevelTld = /^(co|com|org|net|gov|edu|ac)\.[a-z]{2}$/;
  const lastTwo = parts.slice(-2).join(".");
  if (twoLevelTld.test(lastTwo)) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

function isPrivateIp(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(String(ip || ""));
}

function hostOf(u) {
  return String(u || "").replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].toLowerCase();
}

/* OSINT upstream lookups per signal type — read-only intel, safe to run liberally. */
const OSINT = {
  email: ["check_breaches", "email_social_check"],
  domain: ["whois_lookup", "dns_enumeration", "subdomain_enum", "domain_email_search", "ssl_certs"],
  ip: ["ip_geolocation", "shodan_host", "reverse_dns", "greynoise_ip_context"],
  url: ["url_tech_stack", "url_metadata", "url_reputation"],
  eth: ["eth_lookup"],
  asn: ["asn_lookup"],
  hash: ["hash_lookup"],
};
const PLATFORM_TOOL = {
  github: ["github_user_info", "github_commit_emails", "github_user_repos"],
  reddit: ["reddit_user_details"],
  twitter: ["twitter_user_search"],
  instagram: ["instagram_user_lookup"],
  keybase: ["keybase_lookup"],
  steam: ["steam_lookup"],
};
const PER_TYPE_CAP = { email: 10, username: 10, domain: 14, ip: 20, url: 12, social: 12, service: 40, tech: 12, eth: 6, asn: 6, hash: 6, bucket: 8 };
/* Service ports worth a banner grab (web ports are covered by promoting the host). */
const BANNER_PORTS = new Set([21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 1433, 1521, 3306, 5432, 6379, 11211, 27017, 9200, 3389, 5900, 2375, 2379, 9100]);

/* ── HackTricks methodology reference ────────────────────────────────────────
   Attach the relevant HackTricks page to each discovered service/tech so the
   strategist (and the operator) reason with it as the playbook. */
const HT = "https://book.hacktricks.wiki/en";
const HT_NETB = HT + "/network-services-pentesting/";
const HT_WEB = HT + "/network-services-pentesting/pentesting-web";
const HT_METHODOLOGY = HT + "/generic-methodologies-and-resources/pentesting-methodology";
// port -> [exact path segment under network-services-pentesting/, or absolute URL, topic]
// slugs verified against the live site (most are pentesting-<svc>; a few are port-prefixed).
const PORT_GUIDE = {
  21: ["pentesting-ftp", "FTP"], 22: ["pentesting-ssh", "SSH"], 23: ["pentesting-telnet", "Telnet"],
  25: ["pentesting-smtp", "SMTP"], 465: ["pentesting-smtp", "SMTPS"], 587: ["pentesting-smtp", "SMTP submission"],
  53: ["pentesting-dns", "DNS"], 79: ["pentesting-finger", "Finger"],
  110: ["pentesting-pop", "POP3"], 995: ["pentesting-pop", "POP3S"], 143: ["pentesting-imap", "IMAP"], 993: ["pentesting-imap", "IMAPS"],
  111: ["pentesting-rpcbind", "Rpcbind/NFS"], 873: ["873-pentesting-rsync", "rsync"],
  139: ["pentesting-smb", "SMB/NetBIOS"], 445: ["pentesting-smb", "SMB"],
  161: ["pentesting-snmp", "SNMP"], 389: ["pentesting-ldap", "LDAP"], 636: ["pentesting-ldap", "LDAPS"],
  1433: ["pentesting-mssql-microsoft-sql-server", "MSSQL"],
  3306: ["pentesting-mysql", "MySQL"], 3389: ["pentesting-rdp", "RDP"],
  5432: ["pentesting-postgresql", "PostgreSQL"], 5900: ["pentesting-vnc", "VNC"],
  6379: ["6379-pentesting-redis", "Redis"], 27017: ["27017-27018-mongodb", "MongoDB"], 11211: ["11211-memcache", "Memcached"],
  80: [HT_WEB, "Web"], 443: [HT_WEB, "Web"], 8080: [HT_WEB, "Web"], 8443: [HT_WEB, "Web"], 8000: [HT_WEB, "Web"],
};
const TECH_GUIDE = {
  wordpress: [HT_WEB + "/wordpress", "WordPress"], joomla: [HT_WEB + "/joomla", "Joomla"],
  drupal: [HT_WEB + "/drupal", "Drupal"], tomcat: [HT_WEB + "/tomcat", "Tomcat"],
  jira: [HT_WEB + "/jira", "Jira"], graphql: [HT_WEB + "/graphql", "GraphQL"],
  grafana: [HT_WEB + "/grafana", "Grafana"], git: [HT_WEB + "/git", "Git"],
  iis: [HT_WEB + "/iis-internet-information-services", "IIS"], php: [HT_WEB + "/php-tricks-esp", "PHP"],
  symfony: [HT_WEB + "/symphony", "Symfony"], laravel: [HT_WEB + "/laravel", "Laravel"],
  nginx: [HT_WEB + "/nginx", "Nginx"], spring: [HT_WEB + "/spring-actuators", "Spring Boot Actuators"],
};
/* Pentest tools we recognise if a HackTricks page names them (surface as a hint). */
const KNOWN_TOOLS = ["nmap", "hydra", "medusa", "enum4linux", "crackmapexec", "netexec", "smbmap", "smbclient", "rpcclient", "nuclei", "ffuf", "gobuster", "feroxbuster", "sqlmap", "dalfox", "katana", "nikto", "snmpwalk", "onesixtyone", "redis-cli", "showmount", "rsync", "responder", "evil-winrm", "kerbrute", "ldapsearch", "dnsrecon", "wpscan", "hashcat", "john", "metasploit"];

function hacktricksFor(x) {
  if (x.port != null && PORT_GUIDE[x.port]) { const [s, topic] = PORT_GUIDE[x.port]; return { url: s.startsWith("http") ? s : HT_NETB + s, topic }; }
  if (x.product) { const k = String(x.product).toLowerCase(); for (const [key, v] of Object.entries(TECH_GUIDE)) if (k.includes(key)) return { url: v[0], topic: v[1] }; }
  return null;
}
function toolsMentioned(text) { const t = String(text).toLowerCase(); return KNOWN_TOOLS.filter((n) => t.includes(n)); }

/* Produce concrete lead actions from fresh signals, deduped against ctx.done and
   bounded per type. Mutates ctx counters. rootApex scopes active-hunt promotion. */
function planActions(signals, ctx, rootApex) {
  const actions = [];
  ctx.done = ctx.done || new Set();
  ctx.typeCount = ctx.typeCount || {};
  const cap = (type) => (ctx.typeCount[type] = (ctx.typeCount[type] || 0) + 1) <= (PER_TYPE_CAP[type] || 8);
  const push = (key, a) => { if (ctx.done.has(key)) return; ctx.done.add(key); actions.push(a); };
  const up = (server, tool, args, reason) => push(`up:${tool}:${JSON.stringify(args)}`, { kind: "upstream", server, tool, args, reason });

  for (const s of signals || []) {
    const v = s.value;
    switch (s.type) {
      case "email":
        // skip template/placeholder/noreply addresses — they're not real leads
        if (/@(example\.|test\.|sample\.|acme\.|domain\.|yourdomain|your-domain|email\.com|sentry\.|wixpress|\.local$)|^(no-?reply|noreply|donotreply|info@example|you@|user@|name@)/i.test(v)) break;
        if (!cap("email")) break;
        for (const tool of OSINT.email) up("osint", tool, { email: v }, `breach/identity OSINT on ${v}`);
        break;
      case "username":
        if (!cap("username")) break;
        up("osint", "username_search", { username: v }, `cross-platform account search for @${v}`);
        if (s.platform && PLATFORM_TOOL[s.platform]) for (const tool of PLATFORM_TOOL[s.platform]) up("osint", tool, { username: v }, `${s.platform} profile OSINT for @${v}`);
        break;
      case "social":
        if (!cap("social")) break;
        push(`follow:${v}`, { kind: "follow", url: v, reason: `follow ${s.platform || "social"} profile ${v} to harvest identity/contact data` });
        break;
      case "domain": {
        if (!cap("domain")) break;
        const d = v.toLowerCase();
        if (SKIP_DOMAINS.test(d)) break;
        if (rootApex && (d === rootApex || d.endsWith("." + rootApex))) {
          push(`target:${d}`, { kind: "target", target: d, cls: "web", reason: `in-scope subdomain of ${rootApex}` });
        }
        for (const tool of OSINT.domain) up("osint", tool, { domain: d }, `domain intel on ${d}`);
        // keyless subdomain discovery that always works (crt.sh CT logs + subfinder)
        push(`tool:osint.ctsearch:${d}`, { kind: "tool", tool_id: "osint.ctsearch", target: d, reason: `crt.sh CT-log subdomains for ${d}` });
        push(`tool:osint.subs:${d}`, { kind: "tool", tool_id: "osint.subs", target: d, reason: `passive subdomain enum for ${d}` });
        break;
      }
      case "ip":
        if (!cap("ip")) break;
        if (isPrivateIp(v)) push(`target:${v}`, { kind: "target", target: v, cls: "network", reason: `LAN host ${v}` });
        for (const tool of OSINT.ip) up("osint", tool, { ip: v }, `host intel on ${v}`);
        break;
      case "url":
        if (!cap("url")) break;
        for (const tool of OSINT.url) up("osint", tool, { url: v }, `page/tech intel on ${v}`);
        if (rootApex && hostOf(v).endsWith(rootApex)) push(`follow:${v}`, { kind: "follow", url: v, reason: `follow in-scope page ${v}` });
        break;
      case "api_spec":
        push(`tool:api.spec:${v}`, { kind: "tool", tool_id: "api.spec", target: v, reason: `parse API spec ${v}` });
        push(`tool:api.swagger:${v}`, { kind: "tool", tool_id: "api.swagger", target: v, reason: `swagger parse ${v}` });
        break;
      case "service": {
        if (!cap("service")) break;
        const host = s.host, p = Number(s.port);
        if (BANNER_PORTS.has(p)) push(`tool:recon.banner:${host}:${p}`, { kind: "tool", tool_id: "recon.banner", target: host, args: { port: p, timeout: 4 }, reason: `banner-grab ${s.service || p} on ${host}:${p}` });
        const gs = hacktricksFor({ port: p, service: s.service });
        if (gs) push(`ref:${p}:${gs.url}`, { kind: "reference", url: gs.url, topic: gs.topic, host, port: p, reason: `HackTricks ${gs.topic} playbook` });
        break;
      }
      case "tech": {
        if (!cap("tech")) break;
        const gt = hacktricksFor({ product: s.product || v });
        if (gt) push(`ref:tech:${gt.url}`, { kind: "reference", url: gt.url, topic: gt.topic, product: v, reason: `HackTricks ${gt.topic} (detected ${v})` });
        break;
      }
      case "bucket":
        if (!cap("bucket")) break;
        push(`follow:${v}`, { kind: "follow", url: v, reason: `check public object store ${v}` });
        break;
      case "eth": if (cap("eth")) up("osint", "eth_lookup", { value: v }, `ETH address intel ${v}`); break;
      case "asn": if (cap("asn")) up("osint", "asn_lookup", { value: v }, `ASN intel ${v}`); break;
      case "hash": if (cap("hash")) up("osint", "hash_lookup", { value: v }, `hash lookup ${v}`); break;
      default: break; // cve/tech/secret are already recorded as findings by cortex
    }
  }
  return actions;
}

/* A compact, model-readable digest of the signal pool for the strategist prompt. */
function summarizeSignals(signals) {
  const by = {};
  for (const s of signals || []) (by[s.type] = by[s.type] || []).push(s.value);
  return Object.entries(by).map(([t, vs]) => `${t}(${vs.length}): ${[...new Set(vs)].slice(0, 8).join(", ")}`).join("\n");
}

/* Fetch a page and return its text (bounded) so we can extract further signals. */
async function followUrl(url) {
  try {
    const ac = new AbortController();
    const to = setTimeout(() => ac.abort(), 12000);
    const r = await fetch(url, { signal: ac.signal, redirect: "follow", headers: { "user-agent": "Mozilla/5.0 (compatible; suite-recon/1.0)" } });
    clearTimeout(to);
    const body = await r.text();
    return body.slice(0, 500000);
  } catch { return ""; }
}

module.exports = { extractSignals, planActions, summarizeSignals, followUrl, apexOf, isPrivateIp, hostOf, hacktricksFor, toolsMentioned, HT_METHODOLOGY };

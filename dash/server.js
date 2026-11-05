const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const inf = require("./inference");

const PORT = 5321;
const CORTEX = "http://127.0.0.1:5630";
const PUBLIC = path.join(__dirname, "public");
const OPENCODE_BIN = "/Users/maxcallaghan/.opencode/bin/opencode";

function localIps() {
  const nets = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === "IPv4" && !net.internal) {
        ips.push(net.address);
      }
    }
  }
  return ips;
}

function proxy(req, res, pathname, method, data, timeoutMs = 15000) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const r = http.request(
      { host: "127.0.0.1", port: 5630, path: pathname, method,
        headers: { "content-type": "application/json" }, timeout: timeoutMs },
      (pr) => {
        let buf = "";
        pr.on("data", (c) => (buf += c));
        pr.on("end", () => finish({ status: pr.statusCode, body: buf }));
        pr.on("error", () => finish({ status: 502, body: "" }));
        pr.on("aborted", () => finish({ status: 502, body: "" }));
      }
    );
    r.on("timeout", () => { r.destroy(); finish({ status: 504, body: "" }); });
    r.on("error", () => finish({ status: 502, body: "" }));
    if (data) r.write(data);
    r.end();
  });
}

const { execFile } = require("child_process");
const { promisify } = require("util");
const execFileAsync = promisify(execFile);

const net = require("node:net");

function tcpProbe(host, port, timeoutMs = 350) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(open);
    };
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => finish(true));
    sock.once("timeout", () => finish(false));
    sock.once("error", () => finish(false));
    sock.connect(port, host);
  });
}

const PROBE_PORTS = [22, 53, 80, 443, 554, 631, 8000, 8080, 8443, 9100];

async function discoverLocalHosts() {
  const nets = os.networkInterfaces();
  const found = [];
  const seen = new Set();
  for (const name of Object.keys(nets)) {
    for (const n of nets[name] || []) {
      if (n.family !== "IPv4" || n.internal) continue;
      if (!n.address.startsWith("192.168.") && !n.address.startsWith("10.")) continue;
      const prefix = n.address.split(".").slice(0, 3).join(".");
      if (seen.has(prefix)) continue;
      seen.add(prefix);
      const candidates = [];
      for (let i = 1; i <= 254; i++) candidates.push(`${prefix}.${i}`);
      const live = [];
      const batch = 64;
      for (let i = 0; i < candidates.length; i += batch) {
        const slice = candidates.slice(i, i + batch);
        const results = await Promise.all(slice.map(async (ip) => {
          const open = await Promise.all(PROBE_PORTS.map((p) => tcpProbe(ip, p)));
          const openPorts = PROBE_PORTS.filter((_, idx) => open[idx]);
          return openPorts.length ? { ip, ports: openPorts } : null;
        }));
        for (const r of results) if (r) live.push(r);
        if (live.length >= 25) break;
      }
      found.push({ subnet: prefix + ".0/24", hosts: live });
    }
  }
  return found;
}

async function generateTargetSuggestions(requirements) {
  const req = String(requirements || "").toLowerCase();
  const suggestions = [];
  const push = (target, cls, rationale, conf) => suggestions.push({ target, class: cls, rationale, confidence: conf });
  const wantLocal = /local|lan|wi-?fi|home|network|router|gateway|internal|my /.test(req);
  if (wantLocal) {
    for (const ip of localIps()) {
      push(ip, "network", "This machine's address on the local network", "high");
      const gw = ip.split(".").slice(0, 3).join(".") + ".1";
      if (gw !== ip && isUsableTarget(gw)) push(gw, "web", `Default gateway for the ${ip.split(".").slice(0, 3).join(".")}.0/24 subnet`, "high");
    }
    try {
      const found = await discoverLocalHosts();
      for (const subnet of found) {
        for (const h of subnet.hosts) {
          if (suggestions.some((s) => s.target === h.ip)) continue;
          push(h.ip, (h.ports.includes(80) || h.ports.includes(443)) ? "web" : "network",
            `Live host on ${subnet.subnet} — open ports ${h.ports.join(", ")}`, "high");
        }
      }
    } catch {}
  }
  if (/web|website|ecom|store|shop|portal/.test(req)) {
    push("shop.example.com", "web", "Public-facing web storefront / e-commerce portal", "medium");
    push("checkout.example.com", "web", "Checkout / payment page surface", "low");
    push("auth.example.com", "web", "SSO / identity provider login surface", "medium");
  }
  if (/api|graphql|rest|endpoint|microservice/.test(req)) {
    push("api.example.com", "api", "REST/GraphQL API gateway", "medium");
    push("graphql.example.com", "api", "GraphQL endpoint for introspection", "medium");
  }
  if (/mobile|apk|ipa|android|ios/.test(req)) {
    push("m.example.com", "mobile", "Mobile companion app / deep-link surface", "low");
    push("api.mobile.example.com", "api", "Mobile API backend", "low");
  }
  if (/cloud|aws|s3|bucket|azure|gcp|storage/.test(req)) {
    push("files.example.com", "cloud", "Object storage bucket / cloud file host", "low");
    push("cdn.example.com", "cloud", "CDN edge / asset distribution", "low");
  }
  if (/dev|staging|test|uat|internal|intranet/.test(req)) {
    push("dev.example.com", "web", "Development / staging environment", "low");
    push("staging.api.example.com", "api", "Staging API instance", "low");
  }
  if (suggestions.length === 0) {
    for (const ip of localIps()) push(ip, "network", "Local network address available on this machine", "medium");
    if (!suggestions.length) push("example.com", "web", "General public-facing target (no strong keyword match)", "low");
  }
  return suggestions.slice(0, 8);
}

async function callOpenCodeAI(requirements) {
  try {
    const ips = localIps();
    const prompt = `You are a target-scoping assistant for an authorized security assessment.

Respond with ONLY valid JSON, no markdown fences, no prose outside the JSON.
Return an array of up to 6 objects, each with keys:
  target     (string) — a REAL, resolvable host: a domain name (e.g. "shop.acme.com") or an IP (e.g. "192.168.0.28")
  class      (one of: web, api, mobile, binary, network, desktop, other)
  rationale  (string) — one short sentence
  confidence (one of: low, medium, high)

HARD RULES:
- "target" MUST be a hostname or IP address ONLY. Never a description, never a phrase.
- BAD: "router admin web interface", "the main login page", "internal API"
- GOOD: "router.local", "admin.acme.com", "192.168.0.28"
- Use these addresses of the machine running the assessment when they fit: ${ips.join(", ")}
- If the request is about a local/home network, prefer the gateway style addresses and the local IPs above.

Requirements: ${requirements}`;
    const { stdout } = await execFileAsync("expect", ["-c",
      "set timeout 45; set msg $env(MESSAGE); spawn " + OPENCODE_BIN + " run --pure $msg; expect eof",
    ], { timeout: 60000, maxBuffer: 2 * 1024 * 1024, env: { ...process.env, MESSAGE: prompt, NVIDIA_API_KEY: process.env.NVIDIA_API_KEY } });
    const text = stdout || "";
    const clean = text.replace(/\x1b\[[0-9;]*m/g, "").replace(/\x1b\[[0-9?]*[hJK]/g, "").replace(/\r/g, "");
    const start = clean.indexOf("[");
    const end = clean.lastIndexOf("]");
    if (start >= 0 && end > start) {
      const arr = JSON.parse(clean.slice(start, end + 1));
      const valid = arr
        .filter((s) => s && s.target && s.class && s.rationale)
        .filter((s) => isUsableTarget(s.target))
        .map((s) => ({ ...s, target: String(s.target).trim() }));
      if (valid.length) return valid;
    }
  } catch (err) {
    // opencode AI call failed — fall back to local discovery below
  }
  return null;
}

function mapState(raw) {
  const st = raw.state || {};
  const pend = raw.pending;
  let findings = [];
  let negatives = [];
  let evs = [];
  try { findings = JSON.parse(raw.findingsBuf || "[]"); } catch {}
  const approvals = pend
    ? [{ id: pend.id, step: `${pend.tool_id || pend.chain_id}${pend.step != null ? " step " + pend.step : ""}`, blast: pend["reason"] || "", status: pend.decision || "pending" }]
    : [];
  const phaseMap = st.phase === "triaged" ? 0 : st.phase === "understood" ? 1 : st.phase === "chains" ? 2 : st.phase === "exec" ? 3 : 0;
  return {
    mode: st.mode || "plan",
    armed: !!st.armed,
    checkpoint: st.checkpoint || "normal",
    target: st.target || null,
    class: st.class || null,
    approvals,
    findings,
    negsCount: st["negatives_count"] || 0,
    phase: phaseMap,
    dossierTail: raw.dossier || "",
  };
}

const sseClients = new Set();

let eventsCache = [];
function pushEvent(kind, text, data) {
  const ev = { id: eventsCache.length + 1, ts: new Date().toISOString().slice(11, 19), kind, text, data: data || null };
  eventsCache.push(ev);
  if (eventsCache.length > 200) eventsCache.shift();
  for (const res of sseClients) res.write(`data: ${JSON.stringify(ev)}\n\n`);
}

/* Run guard: one pipeline at a time, ever. The browser can ask for a run but
   cannot start a second one, so a stale tab or a double-click cannot loop. */
const runState = { running: false, token: null, startedAt: null, steps: [], target: null, cancelled: false };
const RUN_TTL_MS = 90 * 60 * 1000;

function beginRun(target) {
  if (runState.running) return { ok: false, reason: "already-running", target: runState.target };
  const token = `run_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  runState.running = true;
  runState.token = token;
  runState.startedAt = Date.now();
  runState.steps = [];
  runState.target = target;
  runState.cancelled = false;
  return { ok: true, token };
}

function endRun(token) {
  if (token && runState.token !== token) return;
  runState.running = false;
  runState.token = null;
}

function runStatus() {
  const stale = runState.startedAt && Date.now() - runState.startedAt > RUN_TTL_MS;
  if (stale) endRun(runState.token);
  return { running: runState.running, target: runState.target, steps: runState.steps, started_at: runState.startedAt };
}

/* A real hostname or IP — not a prose description. */
function isUsableTarget(t) {
  const s = String(t || "").trim();
  if (!s || /\s/.test(s)) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return true;
  if (/^https?:\/\//i.test(s)) {
    let h;
    try { h = new URL(s).hostname.replace(/^\[|\]$/g, ""); } catch { return false; }
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h === "localhost" || /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+$/i.test(h);
  }
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+$/i.test(s);
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  const url = new URL(req.url, "http://localhost");

  if (url.pathname === "/events") {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
    sseClients.add(res);
    req.on("close", () => sseClients.delete(res));
    return;
  }

  if (url.pathname === "/api/state") {
    const [stateR, findR, negR] = await Promise.all([
      proxy(req, res, "/state", "GET", undefined, 10000),
      proxy(req, res, "/findings", "GET", undefined, 10000),
      proxy(req, res, "/negatives", "GET", undefined, 10000),
    ]);
    res.writeHead(stateR.status === 502 ? 502 : 200, { "content-type": "application/json" });
    let raw;
    try {
      raw = JSON.parse(stateR.body || "{}");
    } catch {
      res.end(JSON.stringify({ error: "cortex down", down: true }));
      return;
    }
    let findings = [];
    let pendingApproval = raw ? JSON.parse("{\"pending\":null}") : null;
    try { findings = JSON.parse(findR.body || "[]"); } catch {}
    const mapped = mapState({
      state: raw.state || {},
      pending: raw.pending || null,
      findingsBuf: findR.body || "[]",
      negBuf: negR.body || "[]",
      dossier: raw.dossier || "",
    });
    res.end(JSON.stringify(mapped));
    return;
  }

  if (url.pathname === "/api/local-ip") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ips: localIps() }));
    return;
  }

  if (url.pathname === "/api/events-history") {
    const r = await proxy(req, res, "/events-history", "GET");
    try {
      const evs = JSON.parse(r.body || "[]");
      const mapped = evs.map((e, i) => ({
        id: i + 1,
        ts: (e.ts || "").slice(11, 19),
        kind: mapKind(e.kind),
        text: (e.summary || e.kind || "").toString().slice(0, 180),
      })).reverse();
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(mapped));
    } catch {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("[]");
    }
    return;
  }

  if (req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      let data;
      try { data = JSON.parse(body || "{}"); }
      catch { res.writeHead(400, { "content-type": "application/json" }); res.end(JSON.stringify({ ok: false, error: "invalid JSON body" })); return; }
      if (url.pathname === "/api/approve") {
        const decision = data.approve ? "approved" : "denied";
        const r = await proxy(req, res, "/approve", "POST", JSON.stringify({ id: data.id, decision }));
        res.writeHead(200, { "content-type": "application/json" });
        res.end(r.body || "{}");
        return;
      }
      if (url.pathname === "/api/target") {        const r = await proxy(req, res, "/target", "POST", JSON.stringify(data));
        res.writeHead(200, { "content-type": "application/json" });
        res.end(r.body || "{}");
        return;
      }
      if (url.pathname === "/api/mode") {        const r = await proxy(req, res, "/mode", "POST", JSON.stringify({ mode: data.mode }));
        res.writeHead(200, { "content-type": "application/json" });
        res.end(r.body || "{}");
        return;
      }
      if (url.pathname === "/api/arm") {        const r = await proxy(req, res, "/arm", "POST", JSON.stringify({ armed: !!data.armed }));
        res.writeHead(200, { "content-type": "application/json" });
        res.end(r.body || "{}");
        return;
      }
      if (url.pathname === "/api/checkpoint") {        const r = await proxy(req, res, "/checkpoint", "POST", JSON.stringify({ checkpoint: data.level }));
        res.writeHead(200, { "content-type": "application/json" });
        res.end(r.body || "{}");
        return;
      }
      if (url.pathname === "/api/execute") {        const r = await proxy(req, res, "/execute", "POST", JSON.stringify({ tool_id: data.tool_id, args: data.args || {} }));
        pushEvent(r.status >= 400 ? "warn" : "ok", `execute ${data.tool_id}: ${r.status}`);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(r.body || "{}");
        return;
      }
      if (url.pathname === "/api/call_tool") {
        const toolId = data.tool_id || "";
        const target = (data.target || "").trim();
        const args = data.args || {};
        const r = await proxy(req, res, "/call_tool", "POST", JSON.stringify({ tool_id: toolId, target, args }));
        if (toolId !== "list_tools") pushEvent(r.status >= 400 ? "warn" : "ok", `call ${toolId}: ${r.status}`);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(r.body || "{}");
        return;
      }
      if (url.pathname === "/api/pipeline/run") {        const target = String(data.target || "").trim();
        if (!isUsableTarget(target)) {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: `"${target}" is not a real host. Enter a hostname or IP address.` }));
          return;
        }
        const started = beginRun(target);
        if (!started.ok) {
          res.writeHead(409, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "A run is already in progress", run: runStatus() }));
          return;
        }
        res.writeHead(202, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, started: true, token: started.token, target }));
        runPipeline(target, data, started.token);
        return;
      }
      if (url.pathname === "/api/pipeline/status") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(runStatus()));
        return;
      }
      if (url.pathname === "/api/pipeline/stop") {
        const wasRunning = runState.running;
        if (wasRunning) runState.cancelled = true;   // pipeline frees the guard when it unwinds
        else endRun();                               // nothing running: clear any stale flag
        pushEvent("warn", wasRunning ? "pipeline stop requested by user" : "pipeline stopped by user");
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, stopping: wasRunning }));
        return;
      }
      if (url.pathname === "/api/find_target") {        const ai = await callOpenCodeAI(data.requirements);
        const local = await generateTargetSuggestions(data.requirements).catch(() => []);
        const merged = [];
        const seen = new Set();
        for (const s of [...(ai || []), ...local]) {
          if (!s || !isUsableTarget(s.target)) continue;
          const key = String(s.target).toLowerCase();
          if (seen.has(key)) continue;
          seen.add(key);
          merged.push(s);
        }
        const suggestions = merged.slice(0, 8);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, suggestions, count: suggestions.length, ai: Array.isArray(ai) && ai.length > 0 }));
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "unknown api route" }));
      return;
    });
    return;
  }

  if (url.pathname === "/" || url.pathname === "/index.html" || url.pathname === "/console") {
    const file = url.pathname === "/console"
      ? path.join(PUBLIC, "console.html")
      : "/Users/maxcallaghan/Desktop/SUITE Dashboard Redesign.html";
    fs.readFile(file, (err, buf) => {
      if (err) { res.writeHead(500); res.end("missing"); return; }
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store, no-cache, must-revalidate",
        "pragma": "no-cache",
        "expires": "0",
      });
      res.end(buf);
    });
    return;
  }

  res.writeHead(404);
  res.end("nf");
});

function mapKind(kind) {
  const k = String(kind || "");
  if (k.startsWith("web.") || k.startsWith("osint.") || k.startsWith("recon.") || k === "exec") return "scan";
  if (k === "triaged" || k === "understood" || k === "chains_proposed") return "planner";
  if (k === "finding") return "ok";
  if (k === "armed") return "crit";
  if (k === "approval" || k === "approval_requested") return "ledger";
  return "info";
}

/* Server-side pipeline: triage -> understand -> propose -> EXECUTE.
   Runs exactly once per request; the run guard makes that a hard guarantee. */
/* Push a structured strategic event to the dashboard (data.kind drives the console). */
function emitStrategic(kind, text, data) {
  pushEvent(/done|complete|finding/i.test(kind) ? "ok" : kind === "error" || kind === "warn" ? "warn" : "info", text, { kind, ...(data || {}) });
}

/* Merge signals into the hunt's pool, returning only the ones not seen before. */
function addSignals(ctx, sigs) {
  if (!ctx.signalPool) ctx.signalPool = new Map();
  const fresh = [];
  for (const s of sigs || []) {
    const k = s.type + ":" + String(s.value).toLowerCase();
    if (ctx.signalPool.has(k)) continue;
    ctx.signalPool.set(k, s);
    fresh.push(s);
  }
  return fresh;
}

/* AI strategist: given a finished/dead-ended target, infer the NEXT VECTOR — expand to
   the network, pivot to another device, or chain — not just the next tool. Best-effort:
   the caller has a deterministic fallback so the hunt stays relentless if the AI is down. */
async function callStrategist(node, res, ctx) {
  try {
    const ips = localIps();
    const known = (ctx.discoveredHosts || []).map((h) => `${h.ip}(${(h.ports || []).join("/")})`).join(", ") || "none yet";
    const prompt = `You are the strategist for an authorized network penetration test. Decide the NEXT ATTACK VECTOR, not just the next tool.

Context:
- Current target: ${node.target} [class ${node.cls}], reached via: ${node.via}
- Result: ${res.findings || 0} finding(s); ${res.executed || 0} tools run (${res.ranClean || 0} clean / ${res.failed || 0} failed); open ports: ${(res.openPorts || []).map((p) => p.port).join(",") || "none observed"}
- Already visited: ${[...(ctx.visited || [])].join(", ")}
- Other live hosts discovered on the LAN: ${known}
- This machine's addresses: ${ips.join(", ")}
- Leads already harvested (emails/usernames/domains/hosts are chased automatically — do NOT spend vectors on them; focus on which HOSTS/subnets to hunt or pivot to):
${inf.summarizeSignals([...(ctx.signalPool ? ctx.signalPool.values() : [])]).split("\n").map((l) => "    " + l).join("\n") || "    none yet"}
- HackTricks references for what's been found (use these pages as your playbook when deciding vectors):
${[...(ctx.guides || [])].slice(0, 12).map((g) => "    " + g).join("\n") || "    (none yet)"}

Respond with ONLY valid JSON, no prose or fences:
{"rationale":"<1-2 sentences of strategic reasoning>","vectors":[{"action":"expand_network|pivot|chain|stop","target":"<bare host/ip for pivot/chain>","class":"web|api|network|other","reason":"<why>"}]}

Rules: if the current host is a dead end and is a local/router/gateway IP, prefer "expand_network". Use "pivot" to move to a specific discovered host IP that looks more promising (more open ports / web services). "target" MUST be a bare IP or hostname. At most 3 vectors. Use "stop" only if nothing is left.`;
    const { stdout } = await execFileAsync("expect", ["-c",
      "set timeout 45; set msg $env(MESSAGE); spawn " + OPENCODE_BIN + " run --pure $msg; expect eof",
    ], { timeout: 60000, maxBuffer: 2 * 1024 * 1024, env: { ...process.env, MESSAGE: prompt, NVIDIA_API_KEY: process.env.NVIDIA_API_KEY } });
    const clean = (stdout || "").replace(/\x1b\[[0-9;]*m/g, "").replace(/\x1b\[[0-9?]*[hJK]/g, "").replace(/\r/g, "");
    const i = clean.indexOf("{"), j = clean.lastIndexOf("}");
    if (i >= 0 && j > i) {
      const obj = JSON.parse(clean.slice(i, j + 1));
      if (obj && Array.isArray(obj.vectors)) return obj;
    }
  } catch {}
  return null;
}

/* AI inference + deterministic network-expansion fallback. */
async function strategize(node, res, ctx) {
  const vectors = [];
  let rationale = "";
  const isLocal = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(String(node.target)) || node.target === "localhost";
  const ai = await callStrategist(node, res, ctx);
  if (ai && ai.vectors) {
    rationale = ai.rationale || "Strategist proposed next vectors.";
    for (const v of ai.vectors) {
      if (!v || !v.action) continue;
      if ((v.action === "pivot" || v.action === "chain") && !isUsableTarget(v.target || "")) continue;
      vectors.push(v);
    }
  }
  const wantsExpand = vectors.some((v) => v.action === "expand_network");
  if (!res.findings && isLocal && !ctx.expandedNetwork && !wantsExpand) {
    vectors.unshift({ action: "expand_network", reason: `${node.target} yielded nothing — sweep the local subnet for other reachable devices` });
    if (!rationale) rationale = `${node.target} is a dead end. Shifting strategy from this host to the wider network: find other live devices, then pivot to the most exposed one.`;
  }
  if (!rationale) rationale = res.findings ? `${res.findings} finding(s) on ${node.target}.` : `No further vector from ${node.target}.`;
  return { rationale, vectors };
}

/* Hunt ONE target: triage -> (understand/chains for the root only) -> relentless tool run. */
async function huntOneTarget(node, token, mark, stopped, T) {
  const { target, cls, depth } = node;
  const o = T.opts || {};
  const setR = await proxy({}, {}, "/target", "POST", JSON.stringify({ set: target, class: cls }));
  if (setR.status !== 200) { mark("target", "failed", `set ${target} failed`); return { ok: false, findings: 0 }; }
  mark("target", "done", `${target} [${cls}]`);
  await proxy({}, {}, "/mode", "POST", JSON.stringify({ mode: "full" }));
  await proxy({}, {}, "/arm", "POST", JSON.stringify({ armed: true }));
  if (stopped()) return { ok: false, findings: 0, stopped: true };
  const triage = await proxy({}, {}, "/call_tool", "POST", JSON.stringify({ tool_id: "triage_target", target, args: { target, class: cls, notes: `strategic hunt · ${node.via}` } }));
  if (triage.status !== 200) { mark("triage", "failed", "triage failed"); return { ok: false, findings: 0 }; }
  mark("triage", "done", "crate ready");
  // Only the initial target gets the expensive hexstrike-AI understand/propose pass;
  // pivoted/discovered hosts go straight to the relentless tool run for speed.
  if (depth === 0) {
    if (stopped()) return { ok: false, findings: 0, stopped: true };
    const under = await proxy({}, {}, "/call_tool", "POST", JSON.stringify({ tool_id: "understand_target", target, args: { target } }), T.PHASE_TIMEOUT);
    mark("understand", under.status === 200 ? "done" : "failed", under.status === 200 ? "intel captured" : "intel skipped");
    if (stopped()) return { ok: false, findings: 0, stopped: true };
    const chains = await proxy({}, {}, "/call_tool", "POST", JSON.stringify({ tool_id: "propose_chains", target, args: { target } }), T.PHASE_TIMEOUT);
    mark("chains", chains.status === 200 ? "done" : "failed", chains.status === 200 ? "chain proposed" : "default plan");
  }
  if (stopped()) return { ok: false, findings: 0, stopped: true };
  const exec = await proxy({}, {}, "/call_tool", "POST", JSON.stringify({ tool_id: "execute_plan", target, args: { target, max_steps: o.max_steps || 4, relentless: o.relentless !== false, max_tools: o.max_tools || 12, max_rounds: o.max_rounds || 6 } }), T.EXEC_TIMEOUT);
  let parsed = {}; try { parsed = JSON.parse(exec.body || "{}"); } catch {}
  if (exec.status !== 200 || parsed.refused) { mark("execute", "failed", parsed.reason || `refused (${exec.status})`); return { ok: false, findings: 0 }; }
  const results = parsed.results || [];
  const ranClean = results.filter((r) => r.ok).length;
  const failed = results.length - ranClean;
  const openPorts = [];
  for (const r of results) if (Array.isArray(r.open_ports)) openPorts.push(...r.open_ports);
  const signals = [];
  for (const r of results) if (Array.isArray(r.signals)) signals.push(...r.signals);
  mark("execute", "done", `${parsed.executed || 0} tool(s)/${parsed.rounds || 1} round(s) · ${ranClean} ran, ${failed} failed · ${parsed.findings || 0} finding(s) · ${signals.length} signal(s)`);
  return { ok: true, findings: parsed.findings || 0, negatives: parsed.negatives || 0, executed: parsed.executed || 0, rounds: parsed.rounds || 1, ranClean, failed, openPorts, results, signals };
}

/* Strategic hunt: pursue vectors across targets. On a dead end the strategist expands to
   the network and pivots to other devices — an inference loop, not just a tool cycle. */
async function runPipeline(rootTarget, opts, token) {
  const steps = [];
  const PHASE_TIMEOUT = 16 * 60 * 1000;
  const EXEC_TIMEOUT = 45 * 60 * 1000;
  const mark = (name, status, detail) => {
    if (runState.token !== token) return;
    steps.push({ name, status, detail, at: new Date().toISOString() });
    runState.steps = steps.slice();
    pushEvent(status === "done" ? "ok" : status === "failed" ? "warn" : "info", `${name} ${status}${detail ? `: ${detail}` : ""}`);
  };
  const stopped = () => runState.cancelled || runState.token !== token;
  const T = { PHASE_TIMEOUT, EXEC_TIMEOUT, opts };
  const maxTargets = Number(opts.max_targets || 6);
  const ctx = {
    visited: new Set(), discoveredHosts: [], expandedNetwork: false,
    signalPool: new Map(), done: new Set(), typeCount: {},
    leadsRun: 0, maxLeads: Number(opts.max_leads || 60), rootApex: inf.apexOf(rootTarget),
    guides: new Set(),
  };
  const queue = [{ target: rootTarget, cls: opts.class || "web", via: "initial target", depth: 0 }];
  let hunted = 0, totalFindings = 0;

  /* Build the seed signals for a host: the host itself (domain/ip) so OSINT + subdomain
     enumeration ALWAYS runs on it, its open ports as service leads, plus whatever the
     active scan surfaced. */
  const seedFor = (n, res) => {
    const bare = String(n.target).replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
    const seed = [/^\d{1,3}(\.\d{1,3}){3}$/.test(bare) ? { type: "ip", value: bare } : { type: "domain", value: bare }];
    for (const op of (res && res.openPorts) || []) seed.push({ type: "service", value: `${bare}:${op.port}`, host: bare, port: op.port, service: op.service });
    return seed.concat((res && res.signals) || []);
  };

  /* The inference lead-chain: plan actions across the whole cortex surface from the
     current signals (identity/OSINT, subdomains, services, supply-chain, web, cloud…),
     dispatch them, feed second-order signals back in, and promote in-scope hosts to
     full hunts. Passive intel runs freely; bounded by ctx.maxLeads. */
  const leadChain = async (seedSignals, node) => {
    if (stopped()) return;
    const rootUrl = String(node.target).startsWith("http") ? node.target : "http://" + node.target;
    let work = inf.planActions(addSignals(ctx, seedSignals), ctx, ctx.rootApex);
    if (node.depth === 0) work.unshift({ kind: "follow", url: rootUrl, reason: "harvest root page for identity/links" });
    while (work.length && ctx.leadsRun < ctx.maxLeads && !stopped()) {
      const a = work.shift();
      if (a.kind === "target") {
        if (!ctx.visited.has(a.target) && !queue.find((q) => q.target === a.target) && (queue.length + hunted) < maxTargets && isUsableTarget(a.target)) {
          emitStrategic("pivot", `↳ promote ${a.target} to full hunt — ${a.reason}`, { to: a.target, reason: a.reason });
          queue.push({ target: a.target, cls: a.cls || "network", via: a.reason, depth: (node.depth || 0) + 1 });
        }
        continue;
      }
      ctx.leadsRun++;
      let out = "";
      try {
        if (a.kind === "upstream") {
          emitStrategic("lead", `⚑ ${a.tool} ${JSON.stringify(a.args)} — ${a.reason}`, { tool: a.tool, args: a.args });
          const r = await proxy({}, {}, "/call_upstream", "POST", JSON.stringify({ server: a.server, tool: a.tool, args: a.args }), 60000);
          let j = {}; try { j = JSON.parse(r.body || "{}"); } catch {}
          out = String(j.output || j.error || "");
          emitStrategic(j.ok ? "lead_result" : "warn", `   ↳ ${a.tool}: ${(out || "(empty)").replace(/\s+/g, " ").slice(0, 160)}`, { tool: a.tool, ok: !!j.ok });
        } else if (a.kind === "tool") {
          emitStrategic("lead", `⚑ ${a.tool_id} — ${a.reason}`, { tool_id: a.tool_id });
          const r = await proxy({}, {}, "/call_tool", "POST", JSON.stringify({ tool_id: a.tool_id, target: a.target || node.target, args: a.args || {} }), 120000);
          let j = {}; try { j = JSON.parse(r.body || "{}"); } catch {}
          out = String(j.output || j.error || "");
          emitStrategic(j.ok === false ? "warn" : "lead_result", `   ↳ ${a.tool_id}: ${(out || "(done)").replace(/\s+/g, " ").slice(0, 160)}`, { tool_id: a.tool_id });
        } else if (a.kind === "follow") {
          emitStrategic("follow", `↝ fetching ${a.url} — ${a.reason}`, { url: a.url });
          out = await inf.followUrl(a.url);
        } else if (a.kind === "reference") {
          ctx.guides.add(`${a.topic}: ${a.url}`);
          emitStrategic("guide", `📖 HackTricks — ${a.topic}: ${a.url}`, { topic: a.topic, url: a.url, host: a.host, port: a.port });
          const page = await inf.followUrl(a.url);
          const tools = page && page.length > 800 ? inf.toolsMentioned(page) : [];
          if (tools.length) emitStrategic("guide", `   ↳ per HackTricks, relevant tooling: ${tools.slice(0, 10).join(", ")}`, { tools });
          // reference pages are full of example IPs/domains — out stays "" so no signals are extracted from them
        }
      } catch {}
      const fresh = addSignals(ctx, inf.extractSignals(out));
      if (fresh.length) {
        emitStrategic("signals", `   +${fresh.length} new lead(s): ${fresh.slice(0, 6).map((x) => x.type + ":" + x.value).join(", ")}`, { count: fresh.length, items: fresh.slice(0, 20) });
        work = work.concat(inf.planActions(fresh, ctx, ctx.rootApex));
      }
    }
  };

  try {
    mark("start", "info", rootTarget);
    // Up-front passive recon on the target itself — subdomains (crt.sh + subfinder), DNS,
    // whois, breach/identity OSINT, root-page follow — BEFORE the slow active scan, so the
    // inference always runs and discovered subdomains get queued for hunting.
    emitStrategic("recon", `◈ recon pass on ${rootTarget} — subdomains, DNS, whois, OSINT…`, { target: rootTarget });
    ctx.guides.add(`Pentesting methodology: ${inf.HT_METHODOLOGY}`);
    emitStrategic("guide", `📖 HackTricks methodology: ${inf.HT_METHODOLOGY}`, { url: inf.HT_METHODOLOGY });
    await leadChain(seedFor({ target: rootTarget, depth: 0 }, null), { target: rootTarget, depth: 0 });
    while (queue.length && hunted < maxTargets && !stopped()) {
      const node = queue.shift();
      if (!isUsableTarget(node.target) || ctx.visited.has(node.target)) continue;
      ctx.visited.add(node.target); hunted++;
      emitStrategic("vector_start", `▶ pursuing ${node.target} · ${node.via}`, { target: node.target, via: node.via, depth: node.depth });
      const res = await huntOneTarget(node, token, mark, stopped, T);
      totalFindings += res.findings || 0;
      // Inference lead-chain on this host's active-scan results (target + subdomains
      // were already recon'd up-front; this chases what the active tools surfaced).
      if (!res.stopped && !stopped()) await leadChain(seedFor(node, res), node);

      if (res.stopped || stopped() || hunted >= maxTargets) break;
      emitStrategic("strategize", `◆ strategizing from ${node.target}…`, { target: node.target });
      const strat = await strategize(node, res, ctx);
      emitStrategic("strategy", strat.rationale, { rationale: strat.rationale, vectors: strat.vectors });
      for (const v of strat.vectors) {
        if (queue.length + hunted >= maxTargets) break;
        if (v.action === "expand_network") {
          ctx.expandedNetwork = true;
          emitStrategic("network_scan", "⇡ sweeping local subnet for other devices…", {});
          let subnets = [];
          try { subnets = await discoverLocalHosts(); } catch {}
          // Rank discovered hosts by how exposed they are — web/admin ports first,
          // then by total open ports — so we pivot to the juiciest device first.
          const WEB = new Set([80, 443, 8080, 8443, 8000]);
          const ADMIN = new Set([22, 23, 445, 3389, 3306, 5432, 6379, 9100]);
          const score = (h) => (h.ports || []).reduce((s, p) => s + (WEB.has(p) ? 10 : ADMIN.has(p) ? 5 : 1), 0);
          const hosts = [];
          for (const sub of subnets) for (const h of (sub.hosts || [])) {
            if (ctx.visited.has(h.ip) || queue.find((q) => q.target === h.ip) || hosts.find((x) => x.ip === h.ip)) continue;
            hosts.push(h);
          }
          hosts.sort((a, b) => score(b) - score(a));
          for (const h of hosts) {
            ctx.discoveredHosts.push(h);
            const webish = (h.ports || []).some((p) => WEB.has(p));
            emitStrategic("host_discovered", `⊙ discovered ${h.ip} — open ${h.ports.join(", ")}`, { ip: h.ip, ports: h.ports, score: score(h) });
            queue.push({ target: h.ip, cls: webish ? "web" : "network", via: `subnet device (open ${h.ports.join("/")})`, depth: node.depth + 1 });
          }
        } else if ((v.action === "pivot" || v.action === "chain") && isUsableTarget(v.target || "")) {
          if (!ctx.visited.has(v.target) && !queue.find((q) => q.target === v.target)) {
            emitStrategic("pivot", `↳ pivot to ${v.target} — ${v.reason || v.action}`, { from: node.target, to: v.target, reason: v.reason });
            queue.push({ target: v.target, cls: v.class || "network", via: `${v.action}: ${(v.reason || "").slice(0, 70)}`, depth: node.depth + 1 });
          }
        } else if (v.action === "stop") { queue.length = 0; break; }
      }
    }
    emitStrategic("strategic_done", `hunt complete — ${totalFindings} finding(s) across ${hunted} target(s); ${ctx.discoveredHosts.length} device(s) discovered`, { targets: hunted, findings: totalFindings, hosts: ctx.discoveredHosts.length });
    mark("findings", "done", `${totalFindings} finding(s) across ${hunted} target(s)`);
  } catch (err) {
    mark("pipeline", "failed", String(err?.message || err).split("\n")[0]);
  } finally {
    endRun(token);
  }
}

server.listen(PORT, "127.0.0.1", () => console.log(`suite dash (live): http://127.0.0.1:${PORT}`));

let cortexReconnectTimer = null;
function scheduleCortexReconnect(delay = 2000) {
  if (cortexReconnectTimer) return;            // one pending reconnect only
  cortexReconnectTimer = setTimeout(() => {
    cortexReconnectTimer = null;
    connectCortexEvents();
  }, delay);
}
function connectCortexEvents() {
  const creq = http.get(
    "http://127.0.0.1:5630/events",
    { headers: { accept: "text/event-stream" } },
    (cres) => {
      if (cres.statusCode !== 200) { cres.resume(); scheduleCortexReconnect(); return; }
      let buf = "";
      cres.setEncoding("utf8");
      cres.on("data", (c) => {
        buf += c;
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const chunk = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const line = chunk.split("\n").find((l) => l.startsWith("data: "));
          if (!line) continue;
          try {
            const ev = JSON.parse(line.slice(6));
            // Forward the FULL structured cortex event as `data` so the live console
            // can show the current tool, round, elapsed time, output preview, etc.
            pushEvent(mapKind(ev.kind), (ev.summary || ev.kind || "").toString().slice(0, 180), ev);
          } catch {}
        }
      });
      cres.on("end", () => scheduleCortexReconnect());
      cres.on("close", () => scheduleCortexReconnect());
      cres.on("error", () => scheduleCortexReconnect());
    }
  );
  creq.on("error", () => scheduleCortexReconnect());
}
connectCortexEvents();

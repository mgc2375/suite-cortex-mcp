# Suite

The supporting half of the Cortex security-testing suite: the live dashboard, the extracted-tooling arsenal (`suite_tools.py`), the dispatcher that exposes it to Cortex, and the environment fix-up scripts.

Cortex itself — the orchestrator MCP — lives in its own repo: **[mgc2375/cortex-mcp](https://github.com/mgc2375/cortex-mcp)**. This repo is everything *around* it. The ~25 upstream MCPs and heavy tooling (hexstrike-ai, Ghidra, the third-party MCP clones, Python venvs) are **not** vendored here — they're external and cloned/built separately (see Cortex's README).

## What's here

| Path | What it is |
|------|------------|
| `dash/` | The live dashboard — a Node HTTP server (`server.js`) that proxies the Cortex sideband (`127.0.0.1:5630`), an inference layer (`inference.js`), and a browser UI (`public/index.html`, `public/console.html`). Serves on `:5321`. |
| `suite_tools.py` | The toolkit — ~30 standalone recon/OSINT/secret-scanning/wordlist functions extracted for full taxonomy coverage (CT-log mining, TLS/favicon fingerprinting, SPF/DMARC parsing, git-history & paste secret scans, DeHashed breach search, wordlist/mask generation, and more). |
| `mcp/suite-tools/run.py` | CLI dispatcher that exposes a whitelisted set of `suite_tools.py` functions to Cortex (`run.py <function> '<json-args>'`). |
| `fix-tools.sh`, `fix-tools2.sh`, `fix-tools3.sh` | Idempotent, no-sudo scripts that (re)install/repair the hexstrike tools and other binaries Cortex expects on this machine. |
| `captures/_seed.pcap` | Seed capture for the `sipnab` VoIP upstream. |

## How it fits together

```
          browser UI (:5321)
                │
          dash/server.js ──proxy──▶ Cortex sideband (:5630)
                                         │
                                    Cortex MCP ──▶ upstreams + suite-tools
                                                         │
                                         mcp/suite-tools/run.py ──▶ suite_tools.py
```

## Running the dashboard

```bash
cd dash && node server.js      # serves on http://127.0.0.1:5321, proxies Cortex on :5630
```

Cortex must be running (it owns the `:5630` sideband). See the cortex-mcp repo.

## suite_tools directly

```bash
# via the dispatcher (how Cortex calls it)
python3 mcp/suite-tools/run.py ct_log_search '{"domain":"example.com"}'

# run.py with no args lists the exposed functions
python3 mcp/suite-tools/run.py
```

`suite_tools.py` needs `requests` (the dispatcher is run under the hexstrike venv's Python, which has it).

## Environment setup

The `fix-tools*.sh` scripts reinstall the external binaries Cortex's upstreams shell out to. They're safe to re-run and need no sudo:

```bash
./fix-tools.sh      # repairs the hexstrike tools that fail on this machine
./fix-tools2.sh     # the few tools that need git/source installs
./fix-tools3.sh     # everything else Cortex needs that requires an install
```

## Not in this repo

- **Cortex MCP** → [mgc2375/cortex-mcp](https://github.com/mgc2375/cortex-mcp)
- **Upstream MCPs** (`mcps/`) → third-party, each with its own repo; clone/build separately
- **hexstrike-ai**, **Ghidra** (`tools/`), **Python venvs** → external, installed per-machine
- **Secrets** (`.env`, `config.json`) and **node_modules** → git-ignored

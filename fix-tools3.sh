#!/usr/bin/env bash
# Everything else cortex needs that requires an install (the agent can't run installs).
# Safe to re-run. No sudo.
set -u
PY312=/opt/homebrew/bin/python3.12
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/.local/bin:$PATH"
M="$HOME/suite/mcps"

echo "===== 1/3  hexstrike web tools (go -> ~/go/bin) ====="
go install github.com/hahwul/dalfox/v2@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/jaeles-project/jaeles@latest
go install github.com/tomnomnom/waybackurls@latest

echo "===== 2/3  python tools (pipx, Python 3.12) ====="
pipx install checkov --python "$PY312" --force >/dev/null 2>&1 && echo "  checkov ok" || echo "  checkov FAILED"
pipx install prowler --python "$PY312" --force >/dev/null 2>&1 && echo "  prowler ok" || echo "  prowler FAILED"
# wfuzz needs pycurl (libcurl); xsser is git-only for py3 — both are best-effort (ffuf/dalfox cover them)
brew list curl >/dev/null 2>&1 || brew install curl
PYCURL_SSL_LIBRARY=openssl pipx install wfuzz --python "$PY312" --force >/dev/null 2>&1 && echo "  wfuzz ok" || echo "  wfuzz skipped (covered by ffuf)"
pipx install "git+https://github.com/epsylon/xsser.git" --python "$PY312" --force >/dev/null 2>&1 && echo "  xsser ok" || echo "  xsser skipped (covered by dalfox)"

echo "===== 3/3  recreate suite venvs (pyenv, pyenv2) for RE/mobile/CAN/mainframe upstreams ====="
# These MCP servers install from LOCAL source dirs (pyproject.toml), not PyPI.
# clients.js already points at ~/suite/mcps/pyenv*/bin/..., so no code change is needed.
# Move the old broken venvs aside (rm -rf chokes on locked .DS_Store files).
for v in pyenv pyenv2; do [ -e "$M/$v" ] && mv "$M/$v" "$M/$v.broken.$$" 2>/dev/null; done

"$PY312" -m venv "$M/pyenv"
"$M/pyenv/bin/pip" -q install --upgrade pip
echo "  pyenv:  frida-tools + local frida-mcp + local GhidraMCP (+ hack3270 reqs)"
"$M/pyenv/bin/pip" install frida-tools "$M/frida-mcp" "$M/GhidraMCP" 2>&1 | tail -1
[ -f "$M/hack3270/requirements.txt" ] && "$M/pyenv/bin/pip" -q install -r "$M/hack3270/requirements.txt" 2>&1 | tail -1

"$PY312" -m venv "$M/pyenv2"
"$M/pyenv2/bin/pip" -q install --upgrade pip
echo "  pyenv2: peykan + local jadx-mcp-server"
"$M/pyenv2/bin/pip" install peykan "$M/jadx-mcp-server" 2>&1 | tail -1

echo
echo "===== check ====="
for t in dalfox hakrawler jaeles waybackurls checkov prowler; do printf "  %-12s " "$t"; command -v "$t" >/dev/null 2>&1 && echo ok || echo MISSING; done
for f in pyenv/bin/frida-mcp pyenv/bin/ghidra-mcp pyenv/bin/python pyenv2/bin/peykan pyenv2/bin/python; do
  printf "  %-20s " "$f"; [ -e "$M/$f" ] && echo ok || echo MISSING
done
rm -rf "$M"/pyenv.broken.* "$M"/pyenv2.broken.* 2>/dev/null
echo "  (shodan upstream still needs SHODAN_API_KEY / VIRUSTOTAL_API_KEY env vars)"

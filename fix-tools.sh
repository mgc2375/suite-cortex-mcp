#!/usr/bin/env bash
# Reinstalls/repairs the hexstrike tools that fail on this machine.
# Safe to re-run. Nothing here needs sudo.
set -u
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/.local/bin:$PATH"

echo "==> 1/4  ProjectDiscovery tools + gau (go install -> ~/go/bin)"
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest

echo "==> 2/4  Recreating dead pipx venvs (they pointed at the removed /opt/anaconda3)"
PIPX_VENVS="$HOME/Library/Application Support/pipx/venvs"
for p in censys dirsearch fierce hashid kube-hunter netexec paramspider ropper sherlock-project shodan social-analyzer; do
  echo "    - $p"
  pipx uninstall "$p" >/dev/null 2>&1
  rm -rf "$PIPX_VENVS/$p"
  pipx install "$p" >/dev/null 2>&1 || echo "        (install failed for $p — skipping)"
done

echo "==> 3/4  nbtscan (brew)"
brew install nbtscan >/dev/null 2>&1 || echo "    (brew nbtscan skipped)"

echo "==> 4/4  Point hexstrike's shadowing 'httpx' at the real ProjectDiscovery httpx"
if [ -x "$HOME/go/bin/httpx" ]; then
  ln -sf "$HOME/go/bin/httpx" "$HOME/hexstrike-ai/hexstrike_env/bin/httpx"
  echo "    linked venv httpx -> ~/go/bin/httpx"
else
  echo "    WARN: ~/go/bin/httpx not found (go install above may have failed)"
fi

echo
echo "==> DONE. No hexstrike restart needed (tools resolve per call)."
echo "    Quick check:"
for t in httpx katana gau nbtscan; do printf "      %-10s " "$t"; command -v "$t" >/dev/null && echo "ok" || echo "MISSING"; done
for t in netexec fierce dirsearch paramspider; do printf "      %-10s " "$t"; ( "$HOME/.local/bin/$t" --help >/dev/null 2>&1 && echo "ok" ) || echo "check"; done

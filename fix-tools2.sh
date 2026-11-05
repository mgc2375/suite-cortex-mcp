#!/usr/bin/env bash
# The 3 tools that need git/source installs (can't be auto-installed from the agent).
# Safe to re-run. No sudo needed.
set -u
PY312=/opt/homebrew/bin/python3.12
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/.local/bin:$PATH"

echo "==> netexec  (git — not published on PyPI; needs Python 3.12, not 3.14)"
pipx install "git+https://github.com/Pennyw0rth/NetExec.git" --python "$PY312" --force

echo "==> paramspider  (git — not a clean PyPI package)"
pipx install "git+https://github.com/devanshbatham/ParamSpider.git" --force

echo "==> nbtscan  (no brew formula — build from source into ~/go/bin)"
# the earlier build failed because 'automake' was missing (autoreconf needs it)
brew list automake >/dev/null 2>&1 || brew install automake
brew list autoconf >/dev/null 2>&1 || brew install autoconf
rm -rf /tmp/nbtscan-src
if git clone --depth 1 https://github.com/resurrecting-open-source-projects/nbtscan /tmp/nbtscan-src 2>/dev/null; then
  cd /tmp/nbtscan-src
  autoreconf -fi && ./configure && make
  # the binary builds into src/ — copy from wherever it landed
  BIN="$(find /tmp/nbtscan-src -name nbtscan -type f -perm -u+x | head -1)"
  if [ -n "$BIN" ]; then
    cp "$BIN" "$HOME/go/bin/nbtscan" && echo "    nbtscan -> ~/go/bin/nbtscan"
  else
    echo "    nbtscan build failed — see /tmp/nbtscan-src"
  fi
  cd - >/dev/null
else
  echo "    nbtscan clone failed"
fi

echo
echo "==> Check (ropper was already installed by the agent):"
for t in nxc netexec paramspider ropper nbtscan; do
  printf "   %-12s " "$t"; command -v "$t" >/dev/null 2>&1 && echo ok || echo MISSING
done

#!/usr/bin/env bash
# =============================================================================
#  Argus — Zero-API OSINT Engine :: One-Command Installer (Kali / Debian / Ubuntu)
# =============================================================================
#  Usage:
#     git clone https://github.com/mohammedaljohaniit1-max/OSINT-2026.git
#     cd OSINT-2026
#     chmod +x install.sh
#     ./install.sh                 # full install
#     ./install.sh --minimal       # python core only (no external tools)
#     ./install.sh --update        # update tools/templates
#     ./install.sh --with-searxng  # also start local SearXNG (needs docker)
# =============================================================================
set -uo pipefail

RED='\033[31m'; GRN='\033[32m'; YLW='\033[33m'; CYN='\033[36m'; BLD='\033[1m'; RST='\033[0m'
ok(){ echo -e "  ${GRN}[✓]${RST} $*"; }
info(){ echo -e "  ${CYN}[*]${RST} $*"; }
warn(){ echo -e "  ${YLW}[!]${RST} $*"; }
err(){ echo -e "  ${RED}[✗]${RST} $*"; }
step(){ echo -e "\n${BLD}${CYN}══▶ $*${RST}"; }

MINIMAL=0; UPDATE=0; WITH_SEARXNG=0
for a in "$@"; do
  case "$a" in
    --minimal) MINIMAL=1 ;;
    --update) UPDATE=1 ;;
    --with-searxng) WITH_SEARXNG=1 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

cat <<'BANNER'
    ___                           
   /   |  _________ ___  _______  
  / /| | / ___/ __ `/ / / / ___/  
 / ___ |/ /  / /_/ / /_/ (__  )   
/_/  |_/_/   \__, /\__,_/____/    
            /____/   Zero-API OSINT Engine — installer
BANNER

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

# --------------------------------------------------------------------------- #
step "1/7  System packages"
if command -v apt-get >/dev/null 2>&1; then
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq \
    python3 python3-pip python3-venv git curl wget jq \
    dnsutils whois nmap tor libpcap-dev build-essential \
    ca-certificates 2>/dev/null && ok "base packages installed" \
    || warn "some base packages failed (continuing)"
else
  warn "apt not found — install python3/pip/git/nmap manually"
fi

# --------------------------------------------------------------------------- #
step "2/7  Python virtual environment + core"
python3 -m venv .venv 2>/dev/null || true
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip wheel setuptools
pip install --quiet -r requirements.txt && ok "python core installed"
pip install --quiet -e . 2>/dev/null && ok "argus CLI linked (entry point)" \
  || warn "editable install skipped (use: python3 -m argus.cli)"

if [ "$MINIMAL" -eq 1 ]; then
  step "Minimal install complete"
  ok "Run: source .venv/bin/activate && argus doctor"
  exit 0
fi

# --------------------------------------------------------------------------- #
step "3/7  Apt-provided OSINT tools (Kali repos)"
# Kali ships many of these; on plain Debian some may be missing (that's fine).
APT_TOOLS=(theharvester sherlock maigret dnsrecon whatweb sublist3r amass \
           masscan wafw00f dmitry recon-ng photon)
for t in "${APT_TOOLS[@]}"; do
  if $SUDO apt-get install -y -qq "$t" >/dev/null 2>&1; then ok "$t"; else warn "$t not in repo (skipped)"; fi
done

# --------------------------------------------------------------------------- #
step "4/7  Go-based ProjectDiscovery / recon tools"
if ! command -v go >/dev/null 2>&1; then
  info "installing golang…"
  $SUDO apt-get install -y -qq golang-go >/dev/null 2>&1 || warn "install go manually for these tools"
fi
if command -v go >/dev/null 2>&1; then
  export GOBIN="$HOME/.local/bin"; mkdir -p "$GOBIN"
  export PATH="$PATH:$GOBIN"
  GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
  )
  for g in "${GO_TOOLS[@]}"; do
    name="$(basename "${g%@*}")"
    if command -v "$name" >/dev/null 2>&1; then ok "$name (present)"; continue; fi
    info "go install $name …"
    if go install "$g" >/dev/null 2>&1; then ok "$name"; else warn "$name failed"; fi
  done
  # add GOBIN to shell rc
  grep -q '.local/bin' "$HOME/.bashrc" 2>/dev/null || \
    echo 'export PATH="$PATH:$HOME/.local/bin"' >> "$HOME/.bashrc"
fi

# --------------------------------------------------------------------------- #
step "5/7  pipx tools (holehe, etc.)"
python3 -m pip install --quiet pipx 2>/dev/null || true
python3 -m pipx ensurepath >/dev/null 2>&1 || true
for p in holehe maigret; do
  if command -v "$p" >/dev/null 2>&1; then ok "$p (present)"; else
    pipx install "$p" >/dev/null 2>&1 && ok "$p (pipx)" || warn "$p pipx failed"
  fi
done

# --------------------------------------------------------------------------- #
step "6/7  Secret scanners (trufflehog / gitleaks)"
if ! command -v trufflehog >/dev/null 2>&1; then
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | $SUDO sh -s -- -b /usr/local/bin >/dev/null 2>&1 && ok "trufflehog" || warn "trufflehog manual"
else ok "trufflehog (present)"; fi
if ! command -v gitleaks >/dev/null 2>&1; then
  $SUDO apt-get install -y -qq gitleaks >/dev/null 2>&1 && ok "gitleaks" || warn "gitleaks manual"
else ok "gitleaks (present)"; fi

# --------------------------------------------------------------------------- #
step "7/7  Optional local SearXNG (dorking without CAPTCHA)"
if [ "$WITH_SEARXNG" -eq 1 ]; then
  if command -v docker >/dev/null 2>&1; then
    info "starting SearXNG on :8888 …"
    docker run -d --name argus-searxng -p 8888:8080 \
      -e "BASE_URL=http://localhost:8888/" \
      -e "INSTANCE_NAME=argus" searxng/searxng >/dev/null 2>&1 \
      && ok "SearXNG running at http://127.0.0.1:8888" \
      || warn "SearXNG container failed (maybe already running)"
    # enable JSON output
    info "note: ensure 'json' is in SearXNG settings 'formats' for API use"
  else
    warn "docker not installed — SearXNG skipped (dork engine falls back to DuckDuckGo)"
  fi
fi

# nuclei templates
if command -v nuclei >/dev/null 2>&1; then
  info "updating nuclei templates…"; nuclei -update-templates >/dev/null 2>&1 && ok "nuclei templates"
fi

# --------------------------------------------------------------------------- #
echo -e "\n${BLD}${GRN}════════════════════════════════════════════════════════════${RST}"
echo -e "${BLD}${GRN}  Argus installed.${RST}"
echo -e "${BLD}${GRN}════════════════════════════════════════════════════════════${RST}"
echo -e "  Activate env:   ${CYN}source .venv/bin/activate${RST}"
echo -e "  Health check:   ${CYN}argus doctor${RST}   (or: python3 -m argus.cli doctor)"
echo -e "  First scan:     ${CYN}argus scan example.com${RST}"
echo -e "  List modules:   ${CYN}argus modules${RST}"
echo -e "\n  ${YLW}Reminder:${RST} restart your shell or 'source ~/.bashrc' so new PATH tools load."

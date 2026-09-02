#!/usr/bin/env bash
# =============================================================================
#  Argus — Evidence-first OSINT :: Reproducible Installer (Kali/Debian/Ubuntu)
# =============================================================================
#  Usage:
#     git clone https://github.com/mohammedaljohaniit1-max/OSINT-2026.git
#     cd OSINT-2026
#     chmod +x install.sh
#     ./install.sh                 # full install
#     ./install.sh --minimal       # python core only (no external tools)
#     ./install.sh --update        # update tools/templates
#     ./install.sh --with-searxng  # also start local SearXNG (needs docker)
#     ./install.sh --uninstall     # remove venv, reports, SearXNG container, entry point
# =============================================================================
set -uo pipefail

RED='\033[31m'; GRN='\033[32m'; YLW='\033[33m'; CYN='\033[36m'; BLD='\033[1m'; RST='\033[0m'
ok(){ echo -e "  ${GRN}[✓]${RST} $*"; }
info(){ echo -e "  ${CYN}[*]${RST} $*"; }
warn(){ echo -e "  ${YLW}[!]${RST} $*"; }
err(){ echo -e "  ${RED}[✗]${RST} $*"; }
step(){ echo -e "\n${BLD}${CYN}══▶ $*${RST}"; }

MINIMAL=0; UPDATE=0; WITH_SEARXNG=0; UNINSTALL=0

# Reproducible defaults. Override deliberately, e.g. SUBFINDER_VERSION=v2.6.6.
SUBFINDER_VERSION="${SUBFINDER_VERSION:-v2.6.6}"
HTTPX_VERSION="${HTTPX_VERSION:-v1.6.10}"
NAABU_VERSION="${NAABU_VERSION:-v2.3.1}"
NUCLEI_VERSION="${NUCLEI_VERSION:-v3.3.5}"
DNSX_VERSION="${DNSX_VERSION:-v1.2.1}"
GAU_VERSION="${GAU_VERSION:-v2.2.4}"
KATANA_VERSION="${KATANA_VERSION:-v1.1.2}"
for a in "$@"; do
  case "$a" in
    --minimal) MINIMAL=1 ;;
    --update) UPDATE=1 ;;
    --with-searxng) WITH_SEARXNG=1 ;;
    --uninstall|--remove) UNINSTALL=1 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# --------------------------------------------------------------------------- #
#  UNINSTALL — clean removal of everything install.sh created
# --------------------------------------------------------------------------- #
if [ "$UNINSTALL" -eq 1 ]; then
  RED='\033[31m'; GRN='\033[32m'; YLW='\033[33m'; CYN='\033[36m'; BLD='\033[1m'; RST='\033[0m'
  echo -e "${BLD}${CYN}══▶ Uninstalling Argus${RST}"
  SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
  # 1) stop & remove SearXNG container if present
  if command -v docker >/dev/null 2>&1; then
    docker rm -f argus-searxng >/dev/null 2>&1 && echo -e "  ${GRN}[✓]${RST} removed SearXNG container" || true
  fi
  # 2) remove the pip entry point / editable install
  if [ -d ".venv" ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate 2>/dev/null && pip uninstall -y argus-osint >/dev/null 2>&1 || true
    deactivate 2>/dev/null || true
  fi
  python3 -m pip uninstall -y argus-osint >/dev/null 2>&1 || true
  $SUDO rm -f /usr/local/bin/argus /usr/bin/argus 2>/dev/null || true
  # 3) delete the virtual environment
  rm -rf .venv && echo -e "  ${GRN}[✓]${RST} removed .venv"
  # 4) delete generated data (reports + local scan DB)
  rm -rf reports && echo -e "  ${GRN}[✓]${RST} removed reports/ (scan DB + reports)"
  # 5) python caches
  find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
  rm -rf *.egg-info argus.egg-info build dist 2>/dev/null || true
  echo -e "  ${GRN}[✓]${RST} removed build artifacts & caches"
  echo -e "\n${BLD}${GRN}Argus uninstalled.${RST} The source folder is kept; delete it with:"
  echo -e "  ${CYN}cd .. && rm -rf \"$(basename "$ROOT")\"${RST}"
  echo -e "  (External OSINT tools like subfinder/holehe were left installed — they're reusable.)"
  exit 0
fi

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
python -m pip install --quiet --upgrade 'pip<26' 'wheel<1' 'setuptools<82'
python -m pip install --quiet -r requirements.txt && ok "python core installed"
python -m pip install --quiet -e . 2>/dev/null && ok "argus CLI linked (entry point)" \
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
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}"
    "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}"
    "github.com/lc/gau/v2/cmd/gau@${GAU_VERSION}"
    "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}"
  )
  for g in "${GO_TOOLS[@]}"; do
    name="$(basename "${g%@*}")"
    if command -v "$name" >/dev/null 2>&1 && [ "$UPDATE" -eq 0 ]; then ok "$name (present)"; continue; fi
    info "go install $name …"
    if go install "$g" >/dev/null 2>&1; then ok "$name"; else warn "$name failed"; fi
  done
  info "Go tools installed in $GOBIN; add it to PATH in your shell profile if needed"
fi

# --------------------------------------------------------------------------- #
step "5/7  pipx tools (holehe, etc.)"
python3 -m pip install --quiet pipx 2>/dev/null || true
python3 -m pipx ensurepath >/dev/null 2>&1 || true
for p in holehe maigret; do
  if command -v "$p" >/dev/null 2>&1 && [ "$UPDATE" -eq 0 ]; then ok "$p (present)"; else
    pipx install --force "$p" >/dev/null 2>&1 && ok "$p (pipx; version recorded below)" || warn "$p pipx failed"
  fi
done

# --------------------------------------------------------------------------- #
step "6/7  Secret scanners (repository packages only)"
# Never execute remote curl-to-shell installers. Distribution packages are used
# when available; otherwise doctor reports the missing optional capability.
for scanner in trufflehog gitleaks; do
  if command -v "$scanner" >/dev/null 2>&1; then
    ok "$scanner (present)"
  elif $SUDO apt-get install -y -qq "$scanner" >/dev/null 2>&1; then
    ok "$scanner (apt)"
  else
    warn "$scanner unavailable in configured repositories (skipped safely)"
  fi
done

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
# Reproducibility/coverage manifest: exact executable paths and self-reported
# versions. Failures are data, not hidden installer success.
mkdir -p reports
MANIFEST="reports/tool_manifest_$(date -u +%F).tsv"
{
  printf 'tool\tpath\tversion\n'
  for tool in python git go subfinder httpx naabu nuclei dnsx gau katana \
              theHarvester holehe sherlock maigret whatweb trufflehog gitleaks \
              nmap tor docker; do
    path="$(command -v "$tool" 2>/dev/null || true)"
    if [ -n "$path" ]; then
      version="$($tool --version 2>&1 | head -n 1 || true)"
      [ -n "$version" ] || version="$($tool -version 2>&1 | head -n 1 || true)"
      printf '%s\t%s\t%s\n' "$tool" "$path" "${version//$'\t'/ }"
    else
      printf '%s\t%s\t%s\n' "$tool" 'UNAVAILABLE' 'UNAVAILABLE'
    fi
  done
} > "$MANIFEST"
ok "tool/version manifest written to $MANIFEST"

# --------------------------------------------------------------------------- #
echo -e "\n${BLD}${GRN}════════════════════════════════════════════════════════════${RST}"
echo -e "${BLD}${GRN}  Argus installed.${RST}"
echo -e "${BLD}${GRN}════════════════════════════════════════════════════════════${RST}"
echo -e "  Activate env:   ${CYN}source .venv/bin/activate${RST}"
echo -e "  Health check:   ${CYN}argus doctor${RST}   (or: python3 -m argus.cli doctor)"
echo -e "  First scan:     ${CYN}argus scan example.com${RST}"
echo -e "  List modules:   ${CYN}argus modules${RST}"
echo -e "  Scan history:   ${CYN}argus history${RST}   (management commands)"
echo -e "  Manifest:       ${CYN}$MANIFEST${RST}"
echo -e "  Uninstall:      ${CYN}./install.sh --uninstall${RST}"
echo -e "\n  ${YLW}Reminder:${RST} export PATH=\"\$PATH:\$HOME/.local/bin\" if Go/pipx tools are not visible."

#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# install_ofed.sh
#
# Purpose:
#   - Detect Ubuntu version (20.04 / 22.04)
#   - Detect Mellanox/NVIDIA ConnectX generation (ConnectX-3 / 4 / 5 / 6 / 7 / ...)
#   - Select a matching MLNX_OFED tarball and install it
#
# Default policy (edit as needed):
#   - Ubuntu 20.04: MLNX_OFED 24.10-2.1.8.0
#   - Ubuntu 22.04: MLNX_OFED 24.07-0.6.1.0
#   - ConnectX-3 + Ubuntu 20.04: MLNX_OFED 4.9-7.1.0.0 (legacy-friendly)
#
# Notes:
#   - This script targets x86_64 only (as your original script implied).
#   - A reboot is usually recommended after installing OFED.
# -----------------------------------------------------------------------------

SCRIPT_NAME="$(basename "$0")"

log()  { echo "[$SCRIPT_NAME] $*"; }
warn() { echo "[$SCRIPT_NAME] WARNING: $*" >&2; }
die()  { echo "[$SCRIPT_NAME] ERROR: $*" >&2; exit 1; }

# Ensure a required command exists in PATH
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"
}

# Print help/usage
usage() {
  cat <<'EOF'
Usage:
  sudo ./install_ofed.sh [options]

Options:
  -y, --yes                 Non-interactive (assume yes)
  --ofed-version <ver>      Force MLNX_OFED version (override auto selection)
  --dpdk                    Install with --dpdk (default: enabled)
  --no-dpdk                 Do not pass --dpdk
  --add-kernel-support      Pass --add-kernel-support to mlnxofedinstall
  --workdir <dir>           Working directory (default: $HOME)
  -h, --help                Show help

Examples:
  ./install_ofed.sh
  ./install_ofed.sh -y
  ./install_ofed.sh --ofed-version 24.10-2.1.8.0 -y
  ./install_ofed.sh --no-dpdk --add-kernel-support -y
EOF
}

YES=0
FORCED_OFED_VERSION=""
WITH_DPDK=1
ADD_KERNEL_SUPPORT=0
WORKDIR="${HOME}"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) YES=1; shift ;;
    --ofed-version)
      FORCED_OFED_VERSION="${2:-}"
      [[ -n "$FORCED_OFED_VERSION" ]] || die "--ofed-version requires a value"
      shift 2
      ;;
    --dpdk) WITH_DPDK=1; shift ;;
    --no-dpdk) WITH_DPDK=0; shift ;;
    --add-kernel-support) ADD_KERNEL_SUPPORT=1; shift ;;
    --workdir)
      WORKDIR="${2:-}"
      [[ -n "$WORKDIR" ]] || die "--workdir requires a value"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (use -h for help)" ;;
  esac
done

# Validate baseline tools
need_cmd lspci
need_cmd grep
need_cmd sed
need_cmd awk
need_cmd tar

# Pick a downloader (curl preferred; fall back to wget)
if command -v curl >/dev/null 2>&1; then
  DL_TOOL="curl"
elif command -v wget >/dev/null 2>&1; then
  DL_TOOL="wget"
else
  die "Need curl or wget for downloading OFED package."
fi

# Detect Ubuntu version from /etc/os-release and validate supported versions
detect_ubuntu_version() {
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release"
  # shellcheck disable=SC1091
  source /etc/os-release

  [[ "${ID:-}" == "ubuntu" ]] || die "This script only supports Ubuntu (detected: ${ID:-unknown})"

  local ver="${VERSION_ID:-}"
  [[ -n "$ver" ]] || die "Cannot detect Ubuntu VERSION_ID"

  case "$ver" in
    20.04|22.04) echo "$ver" ;;
    *) die "Unsupported Ubuntu version: $ver (only 20.04/22.04 supported)" ;;
  esac
}

# Detect CPU architecture and normalize x86_64 naming
detect_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) echo "x86_64" ;;
    *) die "Unsupported architecture: $arch (this script targets x86_64 only)" ;;
  esac
}

# Detect the first Mellanox/NVIDIA NIC and extract the ConnectX generation number
detect_connectx_gen() {
  local devices first_line gen

  # Many systems show "Mellanox" or "NVIDIA" for NICs; search both
  devices="$(lspci | grep -iE 'mellanox|nvidia' || true)"
  [[ -n "$devices" ]] || die "No Mellanox/NVIDIA NIC found via lspci."

  log "Mellanox/NVIDIA devices found:"
  echo "$devices"
  echo

  first_line="$(echo "$devices" | head -n 1)"
  gen="$(echo "$first_line" | grep -oE 'ConnectX-[0-9]+' | head -n 1 | sed 's/ConnectX-//')"

  if [[ -z "$gen" ]]; then
    warn "Cannot parse ConnectX generation from: $first_line"
    warn "Will treat as 'unknown' and use OS-default OFED mapping."
    echo "unknown"
  else
    echo "$gen"
  fi
}

# Ask for confirmation unless running in non-interactive mode
confirm() {
  local prompt="$1"
  if [[ "$YES" -eq 1 ]]; then
    log "$prompt -> yes (non-interactive)"
    return 0
  fi
  read -r -p "$prompt [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]]
}

main() {
  local ubuntu_ver arch cx_gen ofed_ver url tgz_name dir_name
  local -a install_flags

  ubuntu_ver="$(detect_ubuntu_version)"
  arch="$(detect_arch)"
  cx_gen="$(detect_connectx_gen)"

  log "Detected: Ubuntu $ubuntu_ver, arch=$arch, ConnectX=$cx_gen"
  echo "============================================================"
  echo "This script will install NVIDIA MLNX_OFED on Ubuntu $ubuntu_ver ($arch)."
  echo "Use at your own risk. A reboot is usually recommended after installation."
  echo "============================================================"
  echo

  # Select OFED version based on OS and NIC generation, unless user forces one
  if [[ -n "$FORCED_OFED_VERSION" ]]; then
    ofed_ver="$FORCED_OFED_VERSION"
  else
    if [[ "$cx_gen" == "3" ]]; then
      # Legacy ConnectX-3: keep your original behavior for Ubuntu 20.04 only
      if [[ "$ubuntu_ver" == "20.04" ]]; then
        ofed_ver="4.9-7.1.0.0"
      else
        die "ConnectX-3 detected but Ubuntu is $ubuntu_ver. Use --ofed-version to force a compatible package."
      fi
    else
      # Default mapping for modern NICs (edit as needed)
      case "$ubuntu_ver" in
        20.04) ofed_ver="24.10-2.1.8.0" ;;
        22.04) ofed_ver="24.07-0.6.1.0" ;;
      esac
    fi
  fi

  # Construct tarball name and extracted directory name
  tgz_name="MLNX_OFED_LINUX-${ofed_ver}-ubuntu${ubuntu_ver}-${arch}.tgz"
  dir_name="MLNX_OFED_LINUX-${ofed_ver}-ubuntu${ubuntu_ver}-${arch}"

  # OFED download URL format:
  # https://content.mellanox.com/ofed/MLNX_OFED-<ver>/MLNX_OFED_LINUX-<ver>-ubuntuXX.04-x86_64.tgz
  url="https://content.mellanox.com/ofed/MLNX_OFED-${ofed_ver}/${tgz_name}"

  log "Selected OFED version: $ofed_ver"
  log "Download URL: $url"
  echo

  confirm "Proceed to download & install MLNX_OFED $ofed_ver ?" || die "Aborted by user."

  # Prepare working directory
  mkdir -p "$WORKDIR"
  cd "$WORKDIR"

  # Download package to a stable name: ofed.tgz
  log "Downloading to: $WORKDIR/ofed.tgz"
  rm -f ofed.tgz
  if [[ "$DL_TOOL" == "curl" ]]; then
    curl -fL --retry 3 --retry-delay 2 -o ofed.tgz "$url"
  else
    wget -O ofed.tgz "$url"
  fi

  # Extract tarball
  log "Extracting..."
  rm -rf "$dir_name"
  tar -xvf ofed.tgz

  # Enter extracted directory
  [[ -d "$dir_name" ]] || die "Expected directory not found after extraction: $dir_name"
  cd "$dir_name"

  # Build installer flags
  install_flags=()
  if [[ "$WITH_DPDK" -eq 1 ]]; then
    install_flags+=(--dpdk)
  fi
  if [[ "$ADD_KERNEL_SUPPORT" -eq 1 ]]; then
    install_flags+=(--add-kernel-support)
  fi

  # Run OFED installer
  log "Running installer: sudo ./mlnxofedinstall ${install_flags[*]:-}"
  sudo ./mlnxofedinstall "${install_flags[@]}"

  # Restart openibd if present (some environments may not have it)
  if [[ -x /etc/init.d/openibd ]]; then
    log "Restarting openibd..."
    sudo /etc/init.d/openibd restart
  else
    warn "openibd init script not found; skip restart."
  fi

  echo
  log "MLNX_OFED installation finished."
  log "NOTE: 'failed to update firmware' can be OK depending on environment."
  log "Recommended: reboot the machine to ensure the new driver is fully loaded."
}

main "$@"
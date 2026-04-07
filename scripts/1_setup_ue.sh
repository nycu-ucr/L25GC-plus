#!/usr/bin/bash

# ==============================================================================
# UE/RAN Node Setup Script
# Installs dependencies and builds UERANsim and OAI UE/RAN for 5G User Equipment simulation
# ==============================================================================

set -euo pipefail

# ----[ Constants ]------------------------------------------------------------
WORK_DIR="$HOME"
REPO_DIR="$WORK_DIR/L25GC-plus"
CMAKE_VERSION="3.30.1"
CMAKE_SCRIPT="cmake-${CMAKE_VERSION}-linux-x86_64.sh"

# ----[ System Update and Package Installation ]-------------------------------
echo "[INFO] Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo "[INFO] Installing required development and networking tools..."
sudo apt install make git iperf3 net-tools g++ libsctp-dev lksctp-tools iproute2 -y

# ----[ Install Specific Version of CMake ]------------------------------------
echo "[INFO] Downloading and installing CMake $CMAKE_VERSION..."

cd "$WORK_DIR"
wget -q "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/${CMAKE_SCRIPT}" -O "$CMAKE_SCRIPT"
chmod 744 "$CMAKE_SCRIPT"

# Install CMake into /opt/cmake (or keep default if prompted)
sudo bash "$PWD/$CMAKE_SCRIPT"
# sudo bash "./$CMAKE_SCRIPT"

# Add symlinks to make cmake and friends available system-wide
sudo ln -sf "$WORK_DIR/cmake-${CMAKE_VERSION}-linux-x86_64/bin/"* /usr/local/bin/
# sudo ln -sf "$WORK_DIR/cmake-${CMAKE_VERSION}-linux-x86_64/bin/"* /usr/local/bin/

setup_ueransim() {
	echo "[INFO] Building UERANSIM..."
	cd "$REPO_DIR"
	git submodule sync --recursive
	git submodule update --init --recursive UERANSIM
	cd UERANSIM
	make -j
	echo "[INFO] UERANSIM setup complete."
}

setup_oai() {
	echo "[INFO] Setting up OAI RAN/UE simulator..."
	cd "$WORK_DIR"

	# Prefer repo-managed submodule; if missing, add it. Fall back to direct clone flow.
	if [ -d "$REPO_DIR/.git" ]; then
		if ! git -C "$REPO_DIR" config -f .gitmodules --get submodule.openairinterface5g.path >/dev/null 2>&1; then
			git -C "$REPO_DIR" submodule add https://github.com/openairinterface/openairinterface5g.git openairinterface5g
		fi

		git -C "$REPO_DIR" submodule sync --recursive
		git -C "$REPO_DIR" submodule update --init --recursive openairinterface5g
		OAI_DIR="$REPO_DIR/openairinterface5g"
	else
		if [ ! -d "$WORK_DIR/openairinterface5g/.git" ]; then
			git clone https://github.com/openairinterface/openairinterface5g.git "$WORK_DIR/openairinterface5g"
		fi
		OAI_DIR="$WORK_DIR/openairinterface5g"
	fi

	cd "$OAI_DIR"
	source oaienv
	./cmake_targets/build_oai -I
	cd cmake_targets
	./build_oai --ninja --nrUE --gNB --build-lib telnetsrv
	echo "[INFO] OAI RAN/UE setup complete."
}

# ----[ Install OAI UE/RAN ]------------------------------------
setup_oai

# ----[ Install UERANsim ]------------------------------------
setup_ueransim

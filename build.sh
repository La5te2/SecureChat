#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

PRESET="x64-linux-release"
CONFIG="Release"
BUILD_DIR="out/build/${PRESET}"

if [[ -z "${VCPKG_ROOT:-}" && -d "${HOME}/vcpkg" ]]; then
  export VCPKG_ROOT="${HOME}/vcpkg"
fi

if [[ -z "${VCPKG_ROOT:-}" ]]; then
  echo "ERROR: VCPKG_ROOT must point to your vcpkg checkout."
  echo "Example:"
  echo "  export VCPKG_ROOT=\"\$HOME/vcpkg\""
  exit 1
fi

if [[ ! -f "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" ]]; then
  echo "ERROR: vcpkg toolchain file not found under VCPKG_ROOT:"
  echo "  ${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
  exit 1
fi

echo "[1/3] Checking Linux C++ build tools..."
command -v cmake >/dev/null
command -v ninja >/dev/null
command -v c++ >/dev/null

echo "[2/3] Configuring C++ build directory if needed..."
if [[ ! -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
  cmake --preset "${PRESET}"
else
  echo "CMake cache exists: ${BUILD_DIR}"
fi

echo "[3/3] Building C++ targets..."
cmake --build "${BUILD_DIR}" --config "${CONFIG}"

for output in host client server cert libnative.so; do
  if [[ ! -f "${BUILD_DIR}/${output}" ]]; then
    echo "ERROR: Required native output is missing: ${BUILD_DIR}/${output}"
    exit 1
  fi
done

echo "C++ build completed successfully."
echo "Outputs:"
echo "  ${BUILD_DIR}/host"
echo "  ${BUILD_DIR}/client"
echo "  ${BUILD_DIR}/server"
echo "  ${BUILD_DIR}/cert"
echo "  ${BUILD_DIR}/libnative.so"

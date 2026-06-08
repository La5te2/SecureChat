#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

CONFIG="Release"
WEB_PROJECT="app/web/SecureChat.Web.csproj"
WEB_OBJ="app/web/obj"

echo "[1/2] Building native Linux targets..."
bash ./build.sh

echo "[2/2] Building SecureChat Web for Linux..."
command -v dotnet >/dev/null
dotnet build "${WEB_PROJECT}" -c "${CONFIG}" -r linux-x64 --self-contained false

if [[ -d "${WEB_OBJ}" ]]; then
  echo "Cleaning C# intermediate directory: ${WEB_OBJ}"
  rm -rf "${WEB_OBJ}"
fi

echo "Web build completed successfully."
echo "Run with:"
echo "  dotnet app/web/bin/${CONFIG}/net10.0/linux-x64/SecureChat.Web.dll"

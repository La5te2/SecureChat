#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

PORT="${SECURECHAT_PORT:-25566}"
PID_FILE="${SECURECHAT_PID_FILE:-host.pid}"
LOG_FILE="${SECURECHAT_LOG_FILE:-}"

stop_pid() {
  local pid="$1"
  if [[ -z "${pid}" ]] || ! kill -0 "${pid}" 2>/dev/null; then
    return 0
  fi

  echo "Stopping SecureChat Host: pid ${pid}"
  kill "${pid}" 2>/dev/null || true

  for _ in {1..20}; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done

  echo "Process did not exit after SIGTERM; sending SIGKILL: pid ${pid}"
  kill -9 "${pid}" 2>/dev/null || true
}

pid=""
if [[ -f "${PID_FILE}" ]]; then
  pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
fi

if [[ -z "${pid}" ]] && command -v ss >/dev/null; then
  pid="$(ss -lntp 2>/dev/null | sed -n "/:${PORT} /s/.*pid=\([0-9][0-9]*\).*/\1/p" | head -n 1)"
fi

if [[ -z "${pid}" ]]; then
  pid="$(pgrep -f 'out/build/x64-linux-release/host' | head -n 1 || true)"
fi

if [[ -z "${pid}" ]]; then
  echo "No SecureChat Host process found."
  rm -f "${PID_FILE}"
  exit 0
fi

stop_pid "${pid}"
rm -f "${PID_FILE}"

if command -v ss >/dev/null && ss -lnt 2>/dev/null | grep -q ":${PORT} "; then
  echo "WARNING: TCP port ${PORT} is still listening."
  echo "Inspect it with:"
  echo "  ss -lntp | grep ':${PORT}'"
  exit 1
fi

echo "Host stopped."
if [[ -n "${LOG_FILE}" ]]; then
  echo "Log file kept:"
  echo "  ${LOG_FILE}"
else
  echo "Log file was disabled."
fi

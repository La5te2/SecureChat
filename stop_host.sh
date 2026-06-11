#!/usr/bin/env bash

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_SOURCED=0
if [[ "${SCRIPT_PATH}" != "$0" ]]; then
  SCRIPT_SOURCED=1
fi

if [[ "${SCRIPT_SOURCED}" == "0" ]]; then
  set -euo pipefail
fi

ORIGINAL_DIR="$(pwd)"
cd "$(dirname "${SCRIPT_PATH}")"

PID_FILE="${SECURECHAT_PID_FILE:-host.pid}"
LOG_FILE="${SECURECHAT_LOG_FILE:-}"

clear_securechat_env() {
  unset SECURECHAT_HOST_BIN
  unset SECURECHAT_ROOM
  unset SECURECHAT_PORT
  unset SECURECHAT_SERVER_URL
  unset SECURECHAT_USER
  unset SECURECHAT_PID_FILE
  unset SECURECHAT_LOG_FILE
  unset SECURECHAT_ROOM_PASSWORD
  unset SECURECHAT_ICE_SERVERS
  unset SECURECHAT_SIGNALING_TLS
  unset SECURECHAT_TLS_CERT_FILE
  unset SECURECHAT_TLS_KEY_FILE
  unset SECURECHAT_TLS_KEY_PASS
}

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

main() {
  local pid=""
  if [[ -f "${PID_FILE}" ]]; then
    pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
  fi

  if [[ -z "${pid}" ]] && command -v pgrep >/dev/null; then
    pid="$(pgrep -f 'out/build/x64-linux-release/host' | head -n 1 || true)"
  fi

  if [[ -z "${pid}" ]]; then
    echo "No SecureChat Host process found."
    rm -f "${PID_FILE}"
    clear_securechat_env
    echo "SecureChat runtime environment cleared for this shell process."
    return 0
  fi

  stop_pid "${pid}"
  rm -f "${PID_FILE}"
  clear_securechat_env

  echo "Host stopped."
  echo "SecureChat runtime environment cleared for this shell process."
  if [[ -n "${LOG_FILE}" ]]; then
    echo "Log file kept:"
    echo "  ${LOG_FILE}"
  else
    echo "Log file was disabled."
  fi
}

stop_status=0
main "$@" || stop_status=$?
cd "${ORIGINAL_DIR}" 2>/dev/null || true

if [[ "${SCRIPT_SOURCED}" == "1" ]]; then
  return "${stop_status}"
fi

exit "${stop_status}"

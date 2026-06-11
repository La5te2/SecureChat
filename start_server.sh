#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

SERVER_BIN="${SECURECHAT_SERVER_BIN:-./out/build/x64-linux-release/server}"
PORT="${SECURECHAT_PORT:-25566}"
PID_FILE="${SECURECHAT_SERVER_PID_FILE:-server.pid}"
LOG_FILE="${SECURECHAT_SERVER_LOG_FILE:-}"
# Server is the only role that listens on a public port, so this script starts
# it as a background daemon by default.
# Server output contains room ids, usernames, and connection events.
# Do not persist it unless diagnostics are explicitly requested.
LOG_TARGET="${LOG_FILE:-/dev/null}"
MODE_OVERRIDE=""

if [[ "${EUID}" == "0" && "${SECURECHAT_ALLOW_ROOT:-}" != "1" ]]; then
  echo "ERROR: Refusing to run SecureChat Server as root."
  echo "Create a dedicated user such as 'securechat', or set SECURECHAT_ALLOW_ROOT=1 only for temporary diagnostics."
  exit 1
fi
usage() {
  echo "Usage: ./start_server.sh [--mode ws|wss|insecure|secure|0|1]"
  echo
  echo "Modes:"
  echo "  ws, insecure, 0   Start signaling without TLS."
  echo "  wss, secure, 1    Start signaling with TLS, defaulting to certs/fullchain.pem and certs/privkey.pem."
}

show_log_hint() {
  if [[ -n "${LOG_FILE}" ]]; then
    echo "Log:"
    echo "  tail -f ${LOG_FILE}"
  else
    echo "Log: disabled by default; set SECURECHAT_SERVER_LOG_FILE=server.log to save diagnostics."
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --mode requires ws, wss, insecure, secure, 0, or 1."
        usage
        exit 1
      fi
      MODE_OVERRIDE="$2"
      shift 2
      ;;
    --mode=*)
      MODE_OVERRIDE="${1#--mode=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -n "${MODE_OVERRIDE}" ]]; then
  case "${MODE_OVERRIDE,,}" in
    0|ws|insecure)
      unset SECURECHAT_SIGNALING_TLS
      unset SECURECHAT_TLS_CERT_FILE
      unset SECURECHAT_TLS_KEY_FILE
      unset SECURECHAT_TLS_KEY_PASS
      ;;
    1|wss|secure)
      export SECURECHAT_SIGNALING_TLS=1
      export SECURECHAT_TLS_CERT_FILE="${SECURECHAT_TLS_CERT_FILE:-certs/fullchain.pem}"
      export SECURECHAT_TLS_KEY_FILE="${SECURECHAT_TLS_KEY_FILE:-certs/privkey.pem}"
      ;;
    *)
      echo "ERROR: unsupported --mode value: ${MODE_OVERRIDE}"
      usage
      exit 1
      ;;
  esac
fi

if [[ ! -x "${SERVER_BIN}" ]]; then
  echo "ERROR: Server binary is missing or not executable: ${SERVER_BIN}"
  echo "Build it first:"
  echo "  ./build.sh"
  exit 1
fi

if [[ -f "${PID_FILE}" ]]; then
  old_pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
  if [[ -n "${old_pid}" ]] && kill -0 "${old_pid}" 2>/dev/null; then
    echo "Server is already running: pid ${old_pid}"
    show_log_hint
    exit 0
  fi
  rm -f "${PID_FILE}"
fi

if command -v ss >/dev/null && ss -lnt 2>/dev/null | grep -q ":${PORT} "; then
  echo "ERROR: TCP port ${PORT} is already in use."
  echo "Inspect it with:"
  echo "  ss -lntp | grep ':${PORT}'"
  exit 1
fi

echo "Starting SecureChat Server..."
echo "  port: ${PORT}"

case "${SECURECHAT_SIGNALING_TLS:-}" in
  1|true|TRUE|yes|on)
    tls_enabled=1
    ;;
  *)
    tls_enabled=0
    ;;
esac

if [[ "${tls_enabled}" == "1" ]]; then
  echo "  signaling: wss"
  if [[ -z "${SECURECHAT_TLS_CERT_FILE:-}" || -z "${SECURECHAT_TLS_KEY_FILE:-}" ]]; then
    echo "ERROR: SECURECHAT_TLS_CERT_FILE and SECURECHAT_TLS_KEY_FILE are required for WSS."
    exit 1
  fi
else
  echo "  signaling: ws insecure mode (no TLS)"
fi

env -u SECURECHAT_ROOM_PASSWORD nohup "${SERVER_BIN}" "${PORT}" > "${LOG_TARGET}" 2>&1 &
pid="$!"
echo "${pid}" > "${PID_FILE}"

sleep 1
if kill -0 "${pid}" 2>/dev/null; then
  echo "Server started: pid ${pid}"
  show_log_hint
else
  echo "ERROR: Server exited during startup."
  if [[ -n "${LOG_FILE}" ]]; then
    echo "Last log lines:"
    tail -n 80 "${LOG_FILE}" 2>/dev/null || true
  else
    echo "Logging was disabled; set SECURECHAT_SERVER_LOG_FILE=server.log and retry for diagnostics."
  fi
  rm -f "${PID_FILE}"
  exit 1
fi

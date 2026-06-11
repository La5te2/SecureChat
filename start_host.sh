#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

HOST_BIN="${SECURECHAT_HOST_BIN:-./out/build/x64-linux-release/host}"
SERVER_URL="${SECURECHAT_SERVER_URL:-ws://127.0.0.1:25566}"
ROOM="${SECURECHAT_ROOM:-secure-room}"
USER_NAME="${SECURECHAT_USER:-host}"
PID_FILE="${SECURECHAT_PID_FILE:-host.pid}"
LOG_FILE="${SECURECHAT_LOG_FILE:-}"
# Host is a visible participant. It connects to SERVER_URL and only runs in the
# background when --daemon is explicitly requested.
LOG_TARGET="${LOG_FILE:-/dev/null}"
PASSWORD_SOURCE="prompt"
DAEMON=0

usage() {
  echo "Usage: ./start_host.sh [--server <ws-url>] [--daemon]"
  echo
  echo "Default mode connects this Host as a visible room-owner member to an untrusted Server."
}

show_log_hint() {
  if [[ -n "${LOG_FILE}" ]]; then
    echo "Log:"
    echo "  tail -f ${LOG_FILE}"
  else
    echo "Log: disabled by default; set SECURECHAT_LOG_FILE=host.log to save diagnostics."
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --server requires a ws:// or wss:// URL."
        usage
        exit 1
      fi
      SERVER_URL="$2"
      shift 2
      ;;
    --server=*)
      SERVER_URL="${1#--server=}"
      shift
      ;;
    --daemon)
      DAEMON=1
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


if [[ ! -x "${HOST_BIN}" ]]; then
  echo "ERROR: Host binary is missing or not executable: ${HOST_BIN}"
  echo "Build it first:"
  echo "  ./build.sh"
  exit 1
fi

if [[ "${DAEMON}" != "1" ]]; then
  exec "${HOST_BIN}" --server "${SERVER_URL}" "${ROOM}" "${USER_NAME}"
fi

if [[ -n "${SECURECHAT_ROOM_PASSWORD:-}" ]]; then
  PASSWORD_SOURCE="environment"
elif [[ -t 0 ]]; then
  read -rsp "Room password: " SECURECHAT_ROOM_PASSWORD
  echo
  PASSWORD_SOURCE="hidden prompt"
elif IFS= read -r SECURECHAT_ROOM_PASSWORD; then
  PASSWORD_SOURCE="stdin"
else
  echo "ERROR: room password is required on stdin or SECURECHAT_ROOM_PASSWORD."
  echo "Interactive use:"
  echo "  ./start_host.sh"
  echo "Daemon use:"
  echo "  printf '%s\\n' 'your-password' | ./start_host.sh --daemon"
  exit 1
fi

if [[ -z "${SECURECHAT_ROOM_PASSWORD}" ]]; then
  echo "ERROR: room password is empty."
  exit 1
fi

if [[ -f "${PID_FILE}" ]]; then
  old_pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
  if [[ -n "${old_pid}" ]] && kill -0 "${old_pid}" 2>/dev/null; then
    echo "Host is already running: pid ${old_pid}"
    show_log_hint
    exit 0
  fi
  rm -f "${PID_FILE}"
fi

echo "Starting SecureChat Host..."
echo "  room: ${ROOM}"
echo "  user: ${USER_NAME}"
echo "  password source: ${PASSWORD_SOURCE}"
echo "  server: ${SERVER_URL}"

fifo="$(mktemp -u "${TMPDIR:-/tmp}/securechat-password.XXXXXX")"
mkfifo -m 600 "${fifo}"
cleanup_secret_pipe() {
  rm -f "${fifo}"
}
trap cleanup_secret_pipe EXIT

(
  printf '%s\n' "${SECURECHAT_ROOM_PASSWORD}" > "${fifo}"
) &
writer_pid="$!"
unset SECURECHAT_ROOM_PASSWORD

env -u SECURECHAT_ROOM_PASSWORD nohup "${HOST_BIN}" --server "${SERVER_URL}" "${ROOM}" "${USER_NAME}" --daemon < "${fifo}" > "${LOG_TARGET}" 2>&1 &
pid="$!"
wait "${writer_pid}" 2>/dev/null || true
cleanup_secret_pipe
trap - EXIT
echo "${pid}" > "${PID_FILE}"

sleep 1
if kill -0 "${pid}" 2>/dev/null; then
  echo "Host started: pid ${pid}"
  show_log_hint
else
  echo "ERROR: Host exited during startup."
  if [[ -n "${LOG_FILE}" ]]; then
    echo "Last log lines:"
    tail -n 80 "${LOG_FILE}" 2>/dev/null || true
  else
    echo "Logging was disabled; set SECURECHAT_LOG_FILE=host.log and retry for diagnostics."
  fi
  rm -f "${PID_FILE}"
  exit 1
fi

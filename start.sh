#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

HOST_BIN="${SECURECHAT_HOST_BIN:-./out/build/x64-linux-release/host}"
ROOM="${SECURECHAT_ROOM:-secure-room}"
PORT="${SECURECHAT_PORT:-25566}"
USER_NAME="${SECURECHAT_USER:-host}"
PID_FILE="${SECURECHAT_PID_FILE:-host.pid}"
LOG_FILE="${SECURECHAT_LOG_FILE:-}"
# Host output contains room ids, usernames, ICE state, and connection events.
# Do not persist it unless diagnostics are explicitly requested.
LOG_TARGET="${LOG_FILE:-/dev/null}"
PASSWORD_SOURCE="prompt"

show_log_hint() {
  if [[ -n "${LOG_FILE}" ]]; then
    echo "Log:"
    echo "  tail -f ${LOG_FILE}"
  else
    echo "Log: disabled by default; set SECURECHAT_LOG_FILE=host.log to save diagnostics."
  fi
}

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
  echo "  ./start.sh"
  echo "Non-interactive use:"
  echo "  printf '%s\\n' 'your-password' | ./start.sh"
  exit 1
fi

if [[ -z "${SECURECHAT_ROOM_PASSWORD}" ]]; then
  echo "ERROR: room password is empty."
  exit 1
fi

if [[ -z "${SECURECHAT_ICE_SERVERS:-}" ]]; then
  export SECURECHAT_ICE_SERVERS="stun:stun.cloudflare.com:3478"
fi

if [[ ! -x "${HOST_BIN}" ]]; then
  echo "ERROR: Host binary is missing or not executable: ${HOST_BIN}"
  echo "Build it first:"
  echo "  ./build.sh"
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

if command -v ss >/dev/null && ss -lnt 2>/dev/null | grep -q ":${PORT} "; then
  echo "ERROR: TCP port ${PORT} is already in use."
  echo "Inspect it with:"
  echo "  ss -lntp | grep ':${PORT}'"
  exit 1
fi

echo "Starting SecureChat Host..."
echo "  room: ${ROOM}"
echo "  port: ${PORT}"
echo "  user: ${USER_NAME}"
echo "  ice:  ${SECURECHAT_ICE_SERVERS}"
echo "  password source: ${PASSWORD_SOURCE}"

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

fifo="$(mktemp -u "${TMPDIR:-/tmp}/securechat-password.XXXXXX")"
mkfifo -m 600 "${fifo}"
cleanup_secret_pipe() {
  rm -f "${fifo}"
}
trap cleanup_secret_pipe EXIT

# Feed the password through a short-lived pipe instead of argv or the child
# environment. This keeps the Host process from inheriting SECURECHAT_ROOM_PASSWORD.
(
  printf '%s\n' "${SECURECHAT_ROOM_PASSWORD}" > "${fifo}"
) &
writer_pid="$!"
unset SECURECHAT_ROOM_PASSWORD

env -u SECURECHAT_ROOM_PASSWORD nohup "${HOST_BIN}" "${ROOM}" "${PORT}" "${USER_NAME}" --daemon < "${fifo}" > "${LOG_TARGET}" 2>&1 &
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

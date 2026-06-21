#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

SERVER_BIN="${SECURECHAT_SERVER_BIN:-./out/build/x64-linux-release/server}"
PORT="${SECURECHAT_PORT:-25566}"
PID_FILE="${SECURECHAT_SERVER_PID_FILE:-server.pid}"
LOG_ENABLED="${SECURECHAT_SERVER_LOG_ENABLED:-1}"
LOG_FILE="server/logs/server.log"
# Server 是唯一监听端口的角色，因此启动脚本默认按后台 daemon 运行。
# Server 输出可能包含 room id、用户名和连接事件。
# 默认写入 server/logs/server.log；如果需要丢弃 daemon 输出，
# 设置 SECURECHAT_SERVER_LOG_ENABLED=0。
LOG_TARGET="/dev/null"
MODE_OVERRIDE=""
DEFAULT_TLS_CERT_FILE="certs/fullchain.pem"
DEFAULT_TLS_KEY_FILE="certs/privkey.pem"

if [[ "${EUID}" == "0" && "${SECURECHAT_ALLOW_ROOT:-}" != "1" ]]; then
  echo "ERROR: Refusing to run SecureChat Server as root."
  echo "Create a dedicated user such as 'securechat', or set SECURECHAT_ALLOW_ROOT=1 only for temporary diagnostics."
  exit 1
fi
usage() {
  echo "Usage: ./start_server.sh [--mode wss|secure|1|ws|backend|0]"
  echo
  echo "Public SecureChat entries must use WSS."
  echo "--mode ws/backend starts a loopback WS backend for a TLS proxy or protected tunnel."
  echo "In WSS mode, if TLS env vars are empty, this script uses certs/fullchain.pem and certs/privkey.pem."
  echo "Run the server binary directly with empty TLS env vars to generate a local/LAN development certificate."
}

log_enabled() {
  case "${LOG_ENABLED,,}" in
    1|true|yes|on)
      return 0
      ;;
    0|false|no|off)
      return 1
      ;;
    *)
      echo "ERROR: SECURECHAT_SERVER_LOG_ENABLED must be 1/0, true/false, yes/no, or on/off."
      exit 1
      ;;
  esac
}

show_log_hint() {
  if log_enabled; then
    echo "Log:"
    echo "  tail -f ${LOG_FILE}"
  else
    echo "Log: disabled by SECURECHAT_SERVER_LOG_ENABLED=0."
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --mode requires wss, secure, 1, ws, backend, or 0."
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

BACKEND_WS=0
SERVER_MODE="${MODE_OVERRIDE:-wss}"
case "${SERVER_MODE,,}" in
  0|ws|backend)
    BACKEND_WS=1
    ;;
  1|wss|secure)
    BACKEND_WS=0
    ;;
  insecure)
    echo "ERROR: use --mode backend for a loopback WS backend."
    exit 1
    ;;
  *)
    echo "ERROR: unsupported --mode value: ${SERVER_MODE}"
    usage
    exit 1
    ;;
esac

select_script_tls_defaults() {
  if [[ -n "${SECURECHAT_TLS_CERT_FILE:-}" && -n "${SECURECHAT_TLS_KEY_FILE:-}" ]]; then
    return
  fi

  if [[ -n "${SECURECHAT_TLS_CERT_FILE:-}" || -n "${SECURECHAT_TLS_KEY_FILE:-}" ]]; then
    echo "ERROR: SECURECHAT_TLS_CERT_FILE and SECURECHAT_TLS_KEY_FILE must be set together."
    exit 1
  fi

  export SECURECHAT_TLS_CERT_FILE="${DEFAULT_TLS_CERT_FILE}"
  export SECURECHAT_TLS_KEY_FILE="${DEFAULT_TLS_KEY_FILE}"
  if [[ ! -f "${SECURECHAT_TLS_CERT_FILE}" || ! -f "${SECURECHAT_TLS_KEY_FILE}" ]]; then
    echo "ERROR: start_server.sh expects ${DEFAULT_TLS_CERT_FILE} and ${DEFAULT_TLS_KEY_FILE}."
    echo "This script is for deployment with existing WSS certificates and will not generate local certificates."
    echo "For local/LAN testing, run the server binary directly with SECURECHAT_TLS_CERT_FILE and SECURECHAT_TLS_KEY_FILE unset."
    exit 1
  fi
  echo "Using script default WSS certificate:"
  echo "  cert: ${SECURECHAT_TLS_CERT_FILE}"
  echo "  key:  ${SECURECHAT_TLS_KEY_FILE}"
}

if [[ "${BACKEND_WS}" == "1" ]]; then
  export SECURECHAT_SIGNALING_TLS=0
  if [[ -z "${SECURECHAT_BIND_ADDRESS:-}" ]]; then
    export SECURECHAT_BIND_ADDRESS=127.0.0.1
  fi
  case "${SECURECHAT_BIND_ADDRESS}" in
    127.0.0.1|localhost|::1|\[::1\])
      ;;
    *)
      echo "ERROR: --mode ws/backend requires a loopback bind address."
      echo "Set SECURECHAT_BIND_ADDRESS=127.0.0.1, localhost, or ::1."
      exit 1
      ;;
  esac
else
  export SECURECHAT_SIGNALING_TLS=1
  select_script_tls_defaults
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

if log_enabled; then
  mkdir -p "$(dirname "${LOG_FILE}")"
  LOG_TARGET="${LOG_FILE}"
else
  LOG_TARGET="/dev/null"
fi

echo "Starting SecureChat Server..."
echo "  port: ${PORT}"
if [[ "${BACKEND_WS}" == "1" ]]; then
  echo "  signaling: ws loopback backend"
  echo "  bind: ${SECURECHAT_BIND_ADDRESS}"
else
  echo "  signaling: wss"
  if [[ -z "${SECURECHAT_TLS_CERT_FILE:-}" || -z "${SECURECHAT_TLS_KEY_FILE:-}" ]]; then
    echo "ERROR: SECURECHAT_TLS_CERT_FILE and SECURECHAT_TLS_KEY_FILE are required for WSS."
    exit 1
  fi
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
  if log_enabled; then
    echo "Last log lines:"
    tail -n 80 "${LOG_FILE}" 2>/dev/null || true
  else
    echo "Log output was disabled by SECURECHAT_SERVER_LOG_ENABLED=0."
  fi
  rm -f "${PID_FILE}"
  exit 1
fi

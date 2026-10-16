#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")/.."
SCANNER_PORT=${SCANNER_PORT:-8080}
SCANNER_DB=${SCANNER_DB:-runtime/platform.db}
SCANNER_RULES=${SCANNER_RULES:-vuln-data}
SCANNER_LOG_DIR=${SCANNER_LOG_DIR:-runtime}
SCANNER_BIN=${SCANNER_BIN:-bin}
SCANNER_INPUTS=${SCANNER_INPUTS:-runtime/inputs}
mkdir -p "$SCANNER_INPUTS"
mkdir -p "$SCANNER_LOG_DIR" dist
if [ "${SCANNER_SKIP_BUILD:-0}" != 1 ]; then
  npm --prefix web ci --ignore-scripts
  VITE_DATA_MODE=server npm --prefix web run build
  go build -o dist/sec-server ./cmd/server
  go build -o dist/sec-worker ./cmd/worker
  go build -o dist/sec-updater ./cmd/updater
fi
if curl --silent --connect-timeout 1 --max-time 1 --output /dev/null "http://127.0.0.1:$SCANNER_PORT/healthz"; then
  printf '端口 %s 已有 HTTP 服务，请先停止它或指定 SCANNER_PORT。\n' "$SCANNER_PORT" >&2
  exit 1
fi
server_pid=''
worker_pid=''
updater_pid=''
cleanup() {
  trap - EXIT INT TERM
  for process in "$worker_pid" "$updater_pid" "$server_pid"; do
    if [ -n "$process" ]; then kill "$process" 2>/dev/null || true; fi
  done
  for process in "$worker_pid" "$updater_pid" "$server_pid"; do
    if [ -n "$process" ]; then wait "$process" 2>/dev/null || true; fi
  done
}
trap cleanup EXIT
trap 'exit 0' INT TERM
./dist/sec-server --listen "127.0.0.1:$SCANNER_PORT" --db "$SCANNER_DB" --ui-dir web/dist --seed-demo >"$SCANNER_LOG_DIR/server.log" 2>&1 &
server_pid=$!
attempt=0
until curl --fail --silent "http://127.0.0.1:$SCANNER_PORT/readyz" >/dev/null; do
  if ! kill -0 "$server_pid" 2>/dev/null || [ "$attempt" -ge 100 ]; then cat "$SCANNER_LOG_DIR/server.log"; exit 1; fi
  attempt=$((attempt + 1))
  sleep 0.1
done
if ! kill -0 "$server_pid" 2>/dev/null; then cat "$SCANNER_LOG_DIR/server.log"; exit 1; fi
./dist/sec-worker --server "http://127.0.0.1:$SCANNER_PORT" --bin-dir "$SCANNER_BIN" --rules-dir "$SCANNER_RULES" --inputs-dir "$SCANNER_INPUTS" --runtime-dir "$SCANNER_LOG_DIR/worker" >"$SCANNER_LOG_DIR/worker.log" 2>&1 &
worker_pid=$!
./dist/sec-updater --server "http://127.0.0.1:$SCANNER_PORT" --rules-dir "$SCANNER_RULES" >"$SCANNER_LOG_DIR/updater.log" 2>&1 &
updater_pid=$!
printf '\n打开：http://127.0.0.1:%s\n首次使用在网页设置管理员；已有账号直接登录。\n模拟任务不连接目标；真实扫描只在网页明确选择引擎并创建任务后执行。\n按 Ctrl+C 停止，SQLite 保留在 %s\n' "$SCANNER_PORT" "$SCANNER_DB"
while :; do
  for process in "$server_pid" "$worker_pid" "$updater_pid"; do
    if ! kill -0 "$process" 2>/dev/null; then printf '本地服务退出，请查看 %s 下的日志。\n' "$SCANNER_LOG_DIR" >&2; exit 1; fi
  done
  sleep 1
done

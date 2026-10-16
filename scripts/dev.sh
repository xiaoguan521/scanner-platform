#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")/.."

SCANNER_PORT=${SCANNER_PORT:-8080}
SCANNER_DB=${SCANNER_DB:-runtime/platform.db}
mkdir -p runtime dist
npm --prefix web ci --ignore-scripts
VITE_DATA_MODE=server npm --prefix web run build
go build -o dist/sec-server ./cmd/server
go build -o dist/sec-worker ./cmd/worker

server_pid=''
worker_pid=''
cleanup() {
  trap - EXIT INT TERM
  if [ -n "$worker_pid" ]; then kill "$worker_pid" 2>/dev/null || true; fi
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  if [ -n "$worker_pid" ]; then wait "$worker_pid" 2>/dev/null || true; fi
  if [ -n "$server_pid" ]; then wait "$server_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 0' INT TERM

./dist/sec-server --listen "127.0.0.1:$SCANNER_PORT" --db "$SCANNER_DB" --ui-dir web/dist --seed-demo >runtime/server.log 2>&1 &
server_pid=$!
attempt=0
until curl --fail --silent "http://127.0.0.1:$SCANNER_PORT/readyz" >/dev/null; do
  if ! kill -0 "$server_pid" 2>/dev/null || [ "$attempt" -ge 100 ]; then
    cat runtime/server.log
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done
if ! kill -0 "$server_pid" 2>/dev/null; then cat runtime/server.log; exit 1; fi
./dist/sec-worker --server "http://127.0.0.1:$SCANNER_PORT" >runtime/worker.log 2>&1 &
worker_pid=$!
printf '\n任务页面：http://127.0.0.1:%s/#/tasks\n发现项：http://127.0.0.1:%s/#/findings\n按 Ctrl+C 停止；SQLite 数据保留在 %s\n' "$SCANNER_PORT" "$SCANNER_PORT" "$SCANNER_DB"
wait "$server_pid"

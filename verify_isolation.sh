#!/usr/bin/env bash
# Proves network segmentation from the red-team container's point of view.
# Expected: gateway reachable; llm-sandbox, db and the internet are NOT.
set -u
cd "$(dirname "$0")/.."
probe() {  # name host port expect(open|closed)
  out=$(docker compose --profile tools run --rm --no-deps --entrypoint python red-runner -c "
import socket,sys
try:
    socket.create_connection(('$2',$3),timeout=3); print('open')
except Exception: print('closed')" 2>/dev/null | tail -1)
  [ "$out" = "$4" ] && echo "PASS  red-runner -> $1 is $out" || { echo "FAIL  red-runner -> $1 is $out (expected $4)"; FAILED=1; }
}
FAILED=0
probe gateway gateway 8000 open
probe llm-sandbox llm-sandbox 9000 closed
probe postgres db 5432 closed
probe internet 1.1.1.1 443 closed
exit $FAILED

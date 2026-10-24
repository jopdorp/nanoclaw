#!/bin/sh
# run.sh start|stop|status
D=/userdata/ai/voice
case "${1:-status}" in
start)
  [ -f $D/worker.pid ] && kill -0 "$(cat $D/worker.pid)" 2>/dev/null && { echo running; exit 0; }
  set -a; . $D/voice.env; . $D/host.env; set +a
  nohup $D/venv/bin/python -u $D/worker.py >> $D/worker.log 2>&1 < /dev/null &
  echo $! > $D/worker.pid ;;
stop)
  [ -f $D/worker.pid ] && kill "$(cat $D/worker.pid)" 2>/dev/null; rm -f $D/worker.pid ;;
status)
  [ -f $D/worker.pid ] && kill -0 "$(cat $D/worker.pid)" 2>/dev/null && echo running || echo stopped ;;
esac

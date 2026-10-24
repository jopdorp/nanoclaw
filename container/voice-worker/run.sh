#!/bin/sh
# run.sh start|stop|status. start keeps the worker alive, restarting it with backoff if it dies.
D=/userdata/ai/voice
alive() { [ -f $D/$1.pid ] && kill -0 "$(cat $D/$1.pid)" 2>/dev/null; }
case "${1:-status}" in
start)
  alive loop && { echo running; exit 0; }
  umask 077
  touch $D/worker.log && chmod 600 $D/worker.log
  nohup "$0" loop >> $D/worker.log 2>&1 < /dev/null &
  echo $! > $D/loop.pid ;;
loop)
  delay=1
  while :; do
    began=$(date +%s)
    (set -a; . $D/voice.env; . $D/host.env; exec $D/venv/bin/python -u $D/worker.py) &
    echo $! > $D/worker.pid
    wait $!
    [ $(($(date +%s) - began)) -gt 300 ] && delay=1
    sleep $delay
    [ $delay -lt 30 ] && delay=$((delay * 2))
  done ;;
stop)
  alive loop && kill "$(cat $D/loop.pid)"
  alive worker && kill "$(cat $D/worker.pid)"
  rm -f $D/loop.pid $D/worker.pid ;;
status)
  alive loop && echo running || echo stopped ;;
esac

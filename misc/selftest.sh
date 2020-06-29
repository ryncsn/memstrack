#!/bin/bash

SCRIPT_BASEDIR=$(dirname "$0")
MEMSTRACK_PATH=$(dirname $SCRIPT_BASEDIR)
MEMSTRACK_BIN=$1
MEMSTRACK_OUTPUT=/tmp/memstrack-test

[ -z "$MEMSTRACK_BIN" ] && MEMSTRACK_BIN="$MEMSTRACK_PATH/memstrack"

trap '
rm -rf $MEMSTRACK_OUTPUT
' EXIT

for i in ftrace perf; do
    $MEMSTRACK_BIN \
        --report module_summary,module_top,task_summary,task_top,task_top_json,proc_slab_static \
        --backend $i \
        -o $MEMSTRACK_OUTPUT \
        --notui &

    MEMSTRACK_PID=$!
    if [ ! "$(jobs -r)" ]; then
        echo "ERROR: failed to start tracing"
        exit 1
    fi

    # Wait a while, try to catch some trace event
    sleep 3

    # Check if it failed early
    if [ ! "$(jobs -r)" ]; then
        echo "ERROR: tracing exited unexpectly"
        exit 1
    fi

    kill -INT $MEMSTRACK_PID

    while [ "$(jobs -r)" ]; do
        sleep 1
    done

    if [ ! -s $MEMSTRACK_OUTPUT ]; then
        echo "ERROR: $MEMSTRACK_OUTPUT file is empty"
        exit 1
    fi

    echo "TEST PASS: $i"
done

exit 0

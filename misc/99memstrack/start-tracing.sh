#!/bin/bash

# Currently need mount debugfs to get event id
get_trace_base() {
        if [ -d "/sys/kernel/tracing" ]; then
                echo "/sys/kernel"
        else
                echo "/sys/kernel/debug"
        fi
}

trace_base=$(get_trace_base)
# old debugfs interface case.
if ! [ -d "$trace_base/tracing" ]; then
        mount none -t debugfs $trace_base
        # new tracefs interface case.
elif ! [ -f "$trace_base/tracing/trace" ]; then
        mount none -t tracefs "$trace_base/tracing"
fi

if ! [ -f "$trace_base/tracing/trace" ]; then
        echo "WARN: Mount trace failed for kernel module memory analyzing."
        return 1
fi

memstrack --page --perf --throttle 80 --sort-by peak > /memory-debug & disown

sleep 5

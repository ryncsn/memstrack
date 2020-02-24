#!/bin/bash

type getargnum >/dev/null 2>&1 || . /lib/dracut-lib.sh

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

memstrack_cmdline=$(getargnum 0 0 2 rd.memstrack)

if [ $memstrack_cmdline -gt 1 ]; then
        memstrack --throttle 60 -o /memory-debug & disown
        unset $memstrack_cmdline
fi

if [ $memstrack_cmdline -gt 0 ]; then
        memstrack --summary -o /memory-debug & disown
        unset $memstrack_cmdline
fi

# Wait a second for memstrack to setup everything, avoid missing any event
sleep 1

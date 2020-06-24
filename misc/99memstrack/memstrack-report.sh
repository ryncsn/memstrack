#!/usr/bin/env bash
. /lib/dracut-lib.sh

MEMSTRACK_LEVEL=$(getargnum 0 0 3 rd.memstrack)

if ! [ "$MEMSTRACK_LEVEL" -ge 1 ]; then
    exit 0
fi

if type -P systemctl >/dev/null; then
    systemctl stop memstrack.service
else
    get_pid_of_tracer () {
        local _user _pid _rest
        read _user _pid _rest <<< $(ps aux | grep [m]emstrack | head -1)
        echo $_pid
    }

    kill -s INT $(get_pid_of_tracer)
    while [[ -n $(get_pid_of_tracer) ]]; do
        sleep 1
    done
fi

cat /.memstrack

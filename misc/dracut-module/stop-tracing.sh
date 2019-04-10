#/bin/sh

get_pid_of_tracer () {
    local _user _pid _rest
    read _user _pid _rest <<< $(ps aux | grep memory-tracer | head -1)
    echo $_pid
}

kill -s INT $(get_pid_of_tracer)

while [[ -n $(get_pid_of_tracer) ]]; do
    sleep 1
done

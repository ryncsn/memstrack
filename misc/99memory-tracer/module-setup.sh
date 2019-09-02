#!/usr/bin/bash

check() {
    return 255
}

depends() {
    return 0
}

install() {
    inst "/bin/memory-tracer" "/bin/memory-tracer"

    inst_hook cmdline 00 "$moddir/start-tracing.sh"
    inst_hook cleanup 99 "$moddir/stop-tracing.sh"
}

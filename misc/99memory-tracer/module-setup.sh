#!/usr/bin/bash

check() {
    return 255
}

depends() {
    return 0
}

install() {
    inst "/bin/memory-tracer" "/bin/memory-tracer"
    inst "$moddir/start-tracing.sh" "/bin/memory-tracer-start"
    chmod a+x "$initdir/usr/bin/memory-tracer-start"

    inst "$moddir/memory-tracer.service" "$systemdsystemunitdir/memory-tracer.service"
    ln_r "$systemdsystemunitdir/memory-tracer.service" "$systemdsystemunitdir/sysinit.target.wants/memory-tracer.service"

    inst_hook cleanup 99 "$moddir/stop-tracing.sh"
}

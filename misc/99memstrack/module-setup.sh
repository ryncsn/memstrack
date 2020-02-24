#!/usr/bin/bash

check() {
    return 0
}

depends() {
    return 0
}

install() {
    inst "/bin/memstrack" "/bin/memstrack"
    inst "$moddir/start-tracing.sh" "/bin/memstrack-start"
    chmod a+x "$initdir/usr/bin/memstrack-start"

    inst "$moddir/memstrack.service" "$systemdsystemunitdir/memstrack.service"
    ln_r "$systemdsystemunitdir/memstrack.service" "$systemdsystemunitdir/sysinit.target.wants/memstrack.service"

    inst_hook cleanup 99 "$moddir/stop-tracing.sh"
}
